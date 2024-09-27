//! # Trusted Setup
//!
//! This module provides the functionality to obtain the necessary data for initializing a KZG commitment scheme from a trusted setup output file.
//!
//! The only supported format is the Snark JS `ptau` trusted setup file format.

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
};
use thiserror::Error;

/// Header file type.
const FILE_TYPE: &[u8; 4] = b"ptau";
/// Number of sections.
const N_SECTIONS: usize = 11;
/// File metadata length in bytes.
const METADATA_LEN: usize = 12;
/// Section header length in bytes.
const SECTION_HEADER_LEN: usize = 12;

/// Section ID
#[repr(u8)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SectionId {
    #[default]
    /// Section descriptions.
    Header = 1,
    /// Points tau*G1.
    TauG1 = 2,
    /// Points tau*G2.
    TauG2 = 3,
    /// Points alpha*tau*G1.
    AlphaTauG1 = 4,
    /// Points beta*tau*G1.
    BetaTauG1 = 5,
    /// Single point beta*tau*G2.
    BetaG2 = 6,
    /// Previous contributions.
    Contributions = 7,
    // Phase 2 related sections.
    /// Lagrange basis tau*G1.
    LagrangeG1 = 12,
    /// Lagrange basis tau*G2.
    LagrangeG2 = 13,
    /// Lagrange basis alpha*tau*G1.
    LagrangeAlphaTauG1 = 14,
    /// Lagrange basis beta*tau*G1.
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
    type Error = TrustedSetupError;

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
            _ => Err(TrustedSetupError::UnknownSection(value)),
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
    pub fn load(&self) -> Result<Vec<u8>, io::Error> {
        let mut file = File::open(&self.filepath)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}

/// File Sections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileSections {
    /// Sections
    sections: [SectionInfo; N_SECTIONS as usize],
}

impl FileSections {
    /// Parse the sections from the file data.
    pub fn parse(file_data: &[u8]) -> Result<Self, TrustedSetupError> {
        let mut sections = [SectionInfo::default(); N_SECTIONS];
        let mut offset = METADATA_LEN;

        for i in 0..N_SECTIONS {
            let mut section_header_data = [0u8; SECTION_HEADER_LEN];
            section_header_data.copy_from_slice(&file_data[offset..offset + SECTION_HEADER_LEN]);

            sections[i] = SectionInfo::new_from_data(section_header_data, offset)?;

            offset += SECTION_HEADER_LEN;
        }

        Ok(Self { sections })
    }

    /// Returns the section information.
    pub fn get(&self, id: SectionId) -> Result<&SectionInfo, TrustedSetupError> {
        self.sections
            .get(id.section_index())
            .ok_or(TrustedSetupError::EmptySection(id as u8))
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
    ) -> Result<Self, TrustedSetupError> {
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
pub struct HeaderSection<E: Pairing> {
    /// Curve Field Size
    field_size: u32,
    /// Curve Field Modulus
    field_modulus: <E::BaseField as PrimeField>::BigInt,
    /// Power of the current setup file
    power: u32,
    /// Full ceremony power
    ceremony_power: u32,
}

impl<E: Pairing> HeaderSection<E> {
    fn parse(file_data: &[u8], sections: &FileSections) -> Result<Self, TrustedSetupError> {
        let header_info = sections.get(SectionId::Header)?;
        let mut offset = header_info.position;

        let mut field_size = [0u8; 4];
        field_size.copy_from_slice(&file_data[offset..offset + 4]);
        let field_size = u32::from_le_bytes(field_size);
        offset += 4;

        // Get expected modulus size, rounded up
        let modulus_size = ((E::BaseField::MODULUS_BIT_SIZE + 7) / 8) as usize;

        // Get modulus bytes
        let modulus_bytes = &file_data[offset..(offset + modulus_size)];
        offset += modulus_size;

        // Get selected curve modulus
        let curve_mod = E::BaseField::MODULUS;
        let curve_mod_bytes = curve_mod.to_bytes_le();

        // Check that the obtained modulus is equal to the selected curve modulus
        if modulus_bytes != curve_mod_bytes {
            return Err(TrustedSetupError::FieldModulusMismatch(
                modulus_bytes.to_vec(),
                curve_mod_bytes,
            ));
        }

        let mut power = [0u8; 4];
        power.copy_from_slice(&file_data[offset..offset + 4]);
        let power = u32::from_le_bytes(power);
        offset += 4;

        let mut ceremony_power = [0u8; 4];
        ceremony_power.copy_from_slice(&file_data[offset..offset + 4]);
        let ceremony_power = u32::from_le_bytes(ceremony_power);

        Ok(Self {
            field_size,
            field_modulus: curve_mod,
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
    fn parse(
        file_data: &[u8],
        sections: &FileSections,
        ceremony_power: u32,
    ) -> Result<Self, TrustedSetupError> {
        let header_info = sections.get(SectionId::TauG1)?;

        // Number of elements
        let n_elements = (2u32.pow(ceremony_power)) * 2 - 1;

        // Element size
        let element_size = E::G1Affine::generator().serialized_size(Compress::No);

        // Validate element size
        if element_size != (header_info.size as usize / n_elements as usize) {
            return Err(TrustedSetupError::ElementSizeMismatch);
        }

        // Deserialize each G1 element
        let mut powers: Vec<<E as Pairing>::G1> = Vec::new();
        let mut offset = header_info.position;
        for _ in 0..n_elements {
            let element =
                E::G1Affine::deserialize_uncompressed(&file_data[offset..offset + element_size])
                    .map_err(|e| TrustedSetupError::ParseError(e.to_string()))?;

            powers.push(element.into());
            offset += element_size;
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
    fn parse(
        file_data: &[u8],
        sections: &FileSections,
        ceremony_power: u32,
    ) -> Result<Self, TrustedSetupError> {
        let header_info = sections.get(SectionId::TauG2)?;

        // Number of elements
        let n_elements = 2u32.pow(ceremony_power);

        // Element size
        let element_size = E::G2Affine::generator().serialized_size(Compress::No);

        // Validate element size
        if element_size != (header_info.size as usize / n_elements as usize) {
            return Err(TrustedSetupError::ElementSizeMismatch);
        }

        // Deserialize each G1 element
        let mut powers: Vec<<E as Pairing>::G2> = Vec::new();
        let mut offset = header_info.position;
        for _ in 0..n_elements {
            let element =
                E::G2Affine::deserialize_uncompressed(&file_data[offset..offset + element_size])
                    .map_err(|e| TrustedSetupError::ParseError(e.to_string()))?;

            powers.push(element.into());
            offset += element_size;
        }

        Ok(Self { powers })
    }
}

/// Verifies file metadata.
pub fn verify_metadata(file_data: &[u8]) -> Result<(), TrustedSetupError> {
    let mut file_type = [0u8; 4];
    file_type.copy_from_slice(&file_data[0..4]);

    if file_type != *FILE_TYPE {
        return Err(TrustedSetupError::InvalidFileType(file_type));
    }

    // Version number occupies bytes 4 through 8

    let mut n_sections = [0u8; 4];
    n_sections.copy_from_slice(&file_data[8..12]);
    let n_sections = u32::from_le_bytes(n_sections);

    if n_sections != N_SECTIONS as u32 {
        return Err(TrustedSetupError::InvalidNumberOfSections(n_sections));
    }

    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustedSetupError {
    #[error("Error")]
    Error,
    #[error("IO error: {0}")]
    ParseError(String),
    #[error("Metadata parsing error: {0}")]
    Metadata(String),
    #[error("Invalid file type: {0:?}")]
    InvalidFileType([u8; 4]),
    #[error("Invalid number of sections: {0:?}")]
    InvalidNumberOfSections(u32),
    #[error("Section is uninitialized: {0}")]
    EmptySection(u8),
    #[error("Unknown section ID: {0}")]
    UnknownSection(u8),
    #[error("Field modulus mismatch. Obtained: {0:?}, Expected: {1:?}")]
    FieldModulusMismatch(Vec<u8>, Vec<u8>),
    #[error("Element size mismatch")]
    ElementSizeMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;

    pub const TEST_PTAU_FILEPATH: &str = "ptau/ppot_0080_01.ptau.test";

    #[test]
    fn test_section_id_parsing() {
        assert_eq!(SectionId::try_from(1), Ok(SectionId::Header));
        assert_eq!(SectionId::try_from(2), Ok(SectionId::TauG1));
        assert_eq!(SectionId::try_from(3), Ok(SectionId::TauG2));
        assert!(SectionId::try_from(99).is_err());
    }

    #[test]
    fn test_file_sections() {
        let loader = FileLoader::new(PathBuf::from(TEST_PTAU_FILEPATH));
        let file_data = loader.load().expect("Failed to load the test ptau file");

        verify_metadata(&file_data).expect("Metadata verification failed");

        let sections = FileSections::parse(&file_data).expect("Failed to parse file sections");

        let header_section = sections
            .get(SectionId::Header)
            .expect("Header section missing");

        assert_eq!(header_section.id, SectionId::Header);
    }
}
