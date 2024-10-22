//! # Trusted Setup File Parser
//!
//! This module provides the functionality to obtain the necessary data for initializing a KZG commitment scheme from a trusted setup output file.
//!
//! The only supported format is the Snark JS `ptau` trusted setup file format.

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_std::{io::Cursor, vec::Vec};
use std::{fs::File, io::Read, path::PathBuf};
use thiserror::Error;

/// Header file type.
const FILE_TYPE: &[u8; 4] = b"ptau";
/// Number of sections.
const N_SECTIONS: usize = 11;
/// File metadata length in bytes.
const METADATA_LEN: usize = 12;
/// Section header length in bytes.
const SECTION_HEADER_LEN: usize = 12;

/// G1 and G2 powers of tau tuple type alias.
pub type PowersOfTau<E> = (Vec<<E as Pairing>::G1>, Vec<<E as Pairing>::G2>);

/// Section ID
#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SectionId {
    #[default]
    /// Section descriptions.
    Header = 1,
    /// Points [tau^i]_1
    TauG1 = 2,
    /// Points [tau^i]_2
    TauG2 = 3,
    /// Points [alpha * tau^i]_1
    AlphaTauG1 = 4,
    /// Points [beta * tau^i]_1
    BetaTauG1 = 5,
    /// Single point [beta * tau]_2
    BetaG2 = 6,
    /// Previous contributions.
    Contributions = 7,
    // Phase 2 related sections.
    /// Lagrange basis [tau^i]_1
    LagrangeG1 = 12,
    /// Lagrange basis [tau^i]_2
    LagrangeG2 = 13,
    /// Lagrange basis [alpha * tau^i]_1
    LagrangeAlphaTauG1 = 14,
    /// Lagrange basis [beta * tau^i]_1
    LagrangeBetaTauG1 = 15,
}

impl SectionId {
    /// Returns the section index for the section ID.
    pub fn section_index(&self) -> usize {
        match self {
            SectionId::Header => 0,
            SectionId::TauG1 => 1,
            SectionId::TauG2 => 2,
            SectionId::AlphaTauG1 => 3,
            SectionId::BetaTauG1 => 4,
            SectionId::BetaG2 => 5,
            SectionId::Contributions => 6,
            SectionId::LagrangeG1 => 7,
            SectionId::LagrangeG2 => 8,
            SectionId::LagrangeAlphaTauG1 => 9,
            SectionId::LagrangeBetaTauG1 => 10,
        }
    }
}

impl TryFrom<u8> for SectionId {
    type Error = SetupFileError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SectionId::Header),
            2 => Ok(SectionId::TauG1),
            3 => Ok(SectionId::TauG2),
            4 => Ok(SectionId::AlphaTauG1),
            5 => Ok(SectionId::BetaTauG1),
            6 => Ok(SectionId::BetaG2),
            7 => Ok(SectionId::Contributions),
            12 => Ok(SectionId::LagrangeG1),
            13 => Ok(SectionId::LagrangeG2),
            14 => Ok(SectionId::LagrangeAlphaTauG1),
            15 => Ok(SectionId::LagrangeBetaTauG1),
            _ => Err(SetupFileError::UnknownSection(value)),
        }
    }
}

/// File Loader
pub struct FileLoader {
    filepath: PathBuf,
}

impl FileLoader {
    /// Creates a new instance.
    pub fn new(filepath: PathBuf) -> Self {
        Self { filepath }
    }

    /// Returns the path to the file.
    pub fn filepath(&self) -> &PathBuf {
        &self.filepath
    }

    /// Loads the file.
    pub fn load(&self) -> Result<Vec<u8>, SetupFileError> {
        let mut file =
            File::open(&self.filepath).map_err(|e| SetupFileError::FileError(e.to_string()))?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| SetupFileError::FileError(e.to_string()))?;

        Ok(data)
    }
}

/// File Sections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileSections {
    /// Sections
    sections: [SectionInfo; N_SECTIONS],
}

impl FileSections {
    /// Parse the sections from the file data.
    pub fn parse(file_data: &[u8]) -> Result<Self, SetupFileError> {
        let mut sections = [SectionInfo::default(); N_SECTIONS];
        let mut offset = METADATA_LEN;

        for section in sections.iter_mut() {
            let mut section_header_data = [0u8; SECTION_HEADER_LEN];
            section_header_data.copy_from_slice(&file_data[offset..offset + SECTION_HEADER_LEN]);

            *section = SectionInfo::new_from_data(section_header_data, offset)?;

            offset += SECTION_HEADER_LEN + section.size as usize;
        }

        Ok(Self { sections })
    }

    /// Returns the section information.
    pub fn get(&self, id: SectionId) -> Result<&SectionInfo, SetupFileError> {
        self.sections
            .get(id.section_index())
            .ok_or(SetupFileError::EmptySection(id as u8))
    }
}

/// Section information.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SectionInfo {
    /// ID
    id: SectionId,
    /// Size
    size: u64,
    /// Position
    position: usize,
}

impl SectionInfo {
    /// Create a new instance
    pub fn new_from_data(
        data: [u8; SECTION_HEADER_LEN],
        offset: usize,
    ) -> Result<Self, SetupFileError> {
        // The first four bytes are the section ID, but one is enough.
        let id = SectionId::try_from(data[0])?;

        let mut size = [0u8; 8];
        size.copy_from_slice(&data[4..12]);
        let size: u64 = u64::from_le_bytes(size);

        let position = offset + SECTION_HEADER_LEN;

        Ok(Self { id, position, size })
    }
}

/// Header Section
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderSection {
    /// Curve Field Modulus
    field_modulus: Vec<u8>,
    /// Power of the current setup file
    power: u32,
    /// Full ceremony power
    ceremony_power: u32,
}

impl HeaderSection {
    pub fn parse(file_data: &[u8], sections: &FileSections) -> Result<Self, SetupFileError> {
        let section_info = sections.get(SectionId::Header)?;
        let mut offset = section_info.position;

        // Get the byte length of the field modulus data
        let mut field_mod_size = [0u8; 4];
        field_mod_size.copy_from_slice(&file_data[offset..offset + 4]);
        let field_mod_size = u32::from_le_bytes(field_mod_size);
        offset += 4;

        // Read the field modulus
        let field_modulus = file_data[offset..(offset + field_mod_size as usize)].to_vec();
        offset += field_mod_size as usize;

        let mut power = [0u8; 4];
        power.copy_from_slice(&file_data[offset..offset + 4]);
        let power = u32::from_le_bytes(power);
        offset += 4;

        let mut ceremony_power = [0u8; 4];
        ceremony_power.copy_from_slice(&file_data[offset..offset + 4]);
        let ceremony_power = u32::from_le_bytes(ceremony_power);

        Ok(Self {
            field_modulus,
            power,
            ceremony_power,
        })
    }
}

/// Powers of tau in G1
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TauG1Section<E: Pairing> {
    /// Powers of tau in G1 - [tau^i]_1
    powers: Vec<E::G1>,
}

impl<E: Pairing> TauG1Section<E> {
    pub fn parse(
        file_data: &[u8],
        sections: &FileSections,
        power: u32,
    ) -> Result<Self, SetupFileError> {
        let section_info = sections.get(SectionId::TauG1)?;

        // Number of elements
        let n_elements = (2u32.pow(power)) * 2 - 1;

        // Element size
        let element_size = E::G1Affine::generator().serialized_size(Compress::No);

        // Validate element size
        if section_info.size != element_size as u64 * n_elements as u64 {
            return Err(SetupFileError::ElementSizeMismatch(
                element_size as u64 * n_elements as u64,
                section_info.size,
            ));
        }

        // Deserialize
        let mut powers: Vec<<E as Pairing>::G1> = Vec::new();
        for chunk in file_data
            [section_info.position..section_info.position + section_info.size as usize]
            .chunks_exact(element_size)
            .take(n_elements as usize)
        {
            let mut reader = Cursor::new(chunk);

            let element = E::G1Affine::deserialize_uncompressed_unchecked(&mut reader)
                .map_err(|e| SetupFileError::ParseError(e.to_string()))?;

            powers.push(element.into());
        }

        Ok(Self { powers })
    }
}

/// Powers of tau in G2
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TauG2Section<E: Pairing> {
    /// Powers of tau in G2 - [tau^i]_2
    powers: Vec<E::G2>,
}

impl<E: Pairing> TauG2Section<E> {
    pub fn parse(
        file_data: &[u8],
        sections: &FileSections,
        power: u32,
    ) -> Result<Self, SetupFileError> {
        let section_info = sections.get(SectionId::TauG2)?;

        // Number of elements
        let n_elements = 2u32.pow(power);

        // Element size
        let element_size = E::G2Affine::generator().serialized_size(Compress::No);

        // Validate element size
        if section_info.size != element_size as u64 * n_elements as u64 {
            return Err(SetupFileError::ElementSizeMismatch(
                element_size as u64 * n_elements as u64,
                section_info.size,
            ));
        }

        // Deserialize
        let mut powers: Vec<<E as Pairing>::G2> = Vec::new();
        for chunk in file_data
            [section_info.position..section_info.position + section_info.size as usize]
            .chunks_exact(element_size)
            .take(n_elements as usize)
        {
            let mut reader = Cursor::new(chunk);

            let element = E::G2Affine::deserialize_uncompressed_unchecked(&mut reader)
                .map_err(|e| SetupFileError::ParseError(e.to_string()))?;

            powers.push(element.into());
        }

        Ok(Self { powers })
    }
}

/// Verifies file metadata.
pub fn verify_metadata(file_data: &[u8]) -> Result<(), SetupFileError> {
    let mut file_type = [0u8; 4];
    file_type.copy_from_slice(&file_data[0..4]);

    if file_type != *FILE_TYPE {
        return Err(SetupFileError::InvalidFileType(file_type));
    }

    // Version number occupies bytes 4 through 8

    let mut n_sections = [0u8; 4];
    n_sections.copy_from_slice(&file_data[8..12]);
    let n_sections = u32::from_le_bytes(n_sections);

    if n_sections != N_SECTIONS as u32 {
        return Err(SetupFileError::InvalidNumberOfSections(n_sections));
    }

    Ok(())
}

/// Returns the G1 and G2 powers of tau.
pub fn get_powers_from_file<E: Pairing>(file: &str) -> Result<PowersOfTau<E>, SetupFileError> {
    let file_data = FileLoader::new(PathBuf::from(file)).load()?;
    verify_metadata(&file_data)?;

    let sections = FileSections::parse(&file_data)?;

    let header_section = HeaderSection::parse(&file_data, &sections)?;
    let tau_g1_section = TauG1Section::<E>::parse(&file_data, &sections, header_section.power)?;
    let tau_g2_section = TauG2Section::<E>::parse(&file_data, &sections, header_section.power)?;

    Ok((tau_g1_section.powers, tau_g2_section.powers))
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SetupFileError {
    #[error("Element size mismatch. Obtained: {0:?}, Expected: {1:?}")]
    ElementSizeMismatch(u64, u64),
    #[error("Section is uninitialized: {0}")]
    EmptySection(u8),
    #[error("Field modulus mismatch. Obtained: {0:?}, Expected: {1:?}")]
    FieldModulusMismatch(Vec<u8>, Vec<u8>),
    #[error("File error: {0:?}")]
    FileError(String),
    #[error("Invalid file type: {0:?}")]
    InvalidFileType([u8; 4]),
    #[error("Invalid number of sections: {0:?}")]
    InvalidNumberOfSections(u32),
    #[error("Metadata parsing error: {0}")]
    Metadata(String),
    #[error("IO error: {0}")]
    ParseError(String),
    #[error("Unknown section ID: {0}")]
    UnknownSection(u8),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ff::{BigInt, BigInteger, PrimeField};

    pub const TEST_PTAU_FILEPATH: &str = "ptau/ppot_0080_01.ptau.test";
    pub const TEST_FILE_LEN: usize = 95_634;

    pub const TEST_CEREMONY_POWER: u32 = 28;
    pub const TEST_FILE_POWER: u32 = 1;

    pub const BN254_FIELD_MOD: BigInt<4> = <Bn254 as Pairing>::BaseField::MODULUS;

    #[test]
    fn test_section_id() {
        assert_eq!(SectionId::try_from(1), Ok(SectionId::Header));
        assert_eq!(SectionId::try_from(2), Ok(SectionId::TauG1));
        assert_eq!(SectionId::try_from(3), Ok(SectionId::TauG2));
        assert!(SectionId::try_from(99).is_err());
    }

    #[test]
    fn test_file_loader() {
        let loader = FileLoader::new(PathBuf::from(TEST_PTAU_FILEPATH));
        let file_data = loader.load().expect("Failed to load the test ptau file");

        assert_eq!(file_data.len(), TEST_FILE_LEN);
    }

    #[test]
    fn test_verify_metadata() {
        let loader = FileLoader::new(PathBuf::from(TEST_PTAU_FILEPATH));
        let file_data = loader.load().expect("Failed to load the test ptau file");

        assert_eq!(verify_metadata(&file_data), Ok(()));
    }

    #[test]
    fn test_section_info() {
        let test_section_data = [1, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0];
        let section_info = SectionInfo::new_from_data(test_section_data, 0).unwrap();

        assert_eq!(section_info.id, SectionId::Header);
        assert_eq!(section_info.size, 44);
        assert_eq!(section_info.position, SECTION_HEADER_LEN);
    }

    #[test]
    fn test_file_sections() {
        let loader = FileLoader::new(PathBuf::from(TEST_PTAU_FILEPATH));
        let file_data = loader.load().unwrap();
        let sections = FileSections::parse(&file_data).unwrap();

        for i in 0..N_SECTIONS {
            let section = sections.sections[i];

            // Assert the section index
            let expected_section_index = section.id.section_index();
            assert_eq!(i, expected_section_index);

            assert!(section.size > 0);
            assert!(section.position + section.size as usize <= file_data.len());
        }

        // Assert the section sizes and positions
        for i in 0..N_SECTIONS - 1 {
            let current_section = sections.sections[i];
            let next_section = sections.sections[i + 1];

            // For the header, the position should be METADATA_LEN + SECTION_HEADER_LEN
            if i == 0 {
                assert_eq!(current_section.position, METADATA_LEN + SECTION_HEADER_LEN);
            }

            assert_eq!(
                current_section.position + current_section.size as usize + SECTION_HEADER_LEN,
                next_section.position
            );
        }
    }

    #[test]
    fn test_header_section() {
        let loader = FileLoader::new(PathBuf::from(TEST_PTAU_FILEPATH));
        let file_data = loader.load().unwrap();
        let sections = FileSections::parse(&file_data).unwrap();

        let header_section = HeaderSection::parse(&file_data, &sections).unwrap();

        assert_eq!(
            header_section.field_modulus,
            BN254_FIELD_MOD.to_bytes_le().to_vec()
        );
        assert_eq!(header_section.power, TEST_FILE_POWER);
        assert_eq!(header_section.ceremony_power, TEST_CEREMONY_POWER);
    }

    #[test]
    fn test_tau_g1_section() {
        let loader = FileLoader::new(PathBuf::from(TEST_PTAU_FILEPATH));
        let file_data = loader.load().unwrap();
        let sections = FileSections::parse(&file_data).unwrap();
        let header_section = HeaderSection::parse(&file_data, &sections).unwrap();

        let tau_g1_section =
            TauG1Section::<Bn254>::parse(&file_data, &sections, header_section.power).unwrap();

        assert_eq!(
            tau_g1_section.powers.len(),
            2u32.pow(TEST_FILE_POWER) as usize * 2 - 1
        );
    }

    #[test]
    fn test_tau_g2_section() {
        let loader = FileLoader::new(PathBuf::from(TEST_PTAU_FILEPATH));
        let file_data = loader.load().unwrap();
        let sections = FileSections::parse(&file_data).unwrap();
        let header_section = HeaderSection::parse(&file_data, &sections).unwrap();

        let tau_g2_section =
            TauG2Section::<Bn254>::parse(&file_data, &sections, header_section.power).unwrap();

        assert_eq!(
            tau_g2_section.powers.len(),
            2u32.pow(TEST_FILE_POWER) as usize
        );
    }

    #[test]
    fn test_powers_of_tau() {
        let (g1_pow, g2_pow) = get_powers_from_file::<Bn254>(TEST_PTAU_FILEPATH).unwrap();

        assert_eq!(g1_pow.len(), 2u32.pow(TEST_FILE_POWER) as usize * 2 - 1);
        assert_eq!(g2_pow.len(), 2u32.pow(TEST_FILE_POWER) as usize);
    }
}
