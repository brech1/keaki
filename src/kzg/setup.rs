//! # KZG Setup Module
//!
//! This module contains helpers for the KZG Setup.

use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::Validate;
use ark_serialize::{CanonicalSerialize, Compress};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    marker::PhantomData,
    path::PathBuf,
};

// Hash Size in bytes
pub const HASH_SIZE: usize = 64;

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

/// File Description
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileDescription {
    /// File Type
    file_type: [u8; 4],
    /// Version Number
    version: u32,
    /// Number of Sections
    n_sections: u32,
    /// Sections
    sections: BTreeMap<u32, Vec<FileSection>>,
}

impl FileDescription {
    /// Parse the file description from binary data
    pub fn from_bytes(file_data: &[u8]) -> Result<FileDescription, String> {
        println!("File Data Length: {}", file_data.len());
        if file_data.len() < 12 {
            return Err("File too short to contain a valid header.".to_string());
        }

        // Read the file type (first 4 bytes)
        let file_type = file_data[0..4]
            .try_into()
            .map_err(|_| "Failed to read file type")?;

        // Read the version number (next 4 bytes as u32)
        let version = u32::from_le_bytes(
            file_data[4..8]
                .try_into()
                .map_err(|_| "Failed to read version")?,
        );

        // Read the number of sections (next 4 bytes as u32)
        let n_sections = u32::from_le_bytes(
            file_data[8..12]
                .try_into()
                .map_err(|_| "Failed to read number of sections")?,
        );

        println!("Number of Sections: {}", n_sections);

        let mut sections = BTreeMap::new();
        let mut offset = 12;

        // Loop over the number of sections
        for _ in 0..n_sections {
            if offset + 12 > file_data.len() {
                return Err("File too short to read all sections.".to_string());
            }

            // Read section type (4 bytes)
            let section_type = u32::from_le_bytes(
                file_data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "Failed to read section type")?,
            );

            // Read section size (next 8 bytes)
            let size = u64::from_le_bytes(
                file_data[offset + 4..offset + 12]
                    .try_into()
                    .map_err(|_| "Failed to read section size")?,
            );

            // Current position in the file
            let position = offset as u64;

            // Create or append to the list of sections for this type
            sections
                .entry(section_type)
                .or_insert_with(Vec::new)
                .push(FileSection { position, size });

            offset += 12 + size as usize; // Move to the next section entry
        }

        Ok(FileDescription {
            file_type,
            version,
            n_sections,
            sections,
        })
    }
}

/// File Section
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileSection {
    /// Position
    position: u64,
    /// Size
    size: u64,
}

impl FileSection {
    /// Create a new file section.
    pub fn new(position: u64, size: u64) -> Self {
        Self { position, size }
    }
}

/// File Header
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileHeader<E: Pairing> {
    pub header_type: u32,
    pub header_length: u64,
    pub field_size: u32,
    pub q: <E::BaseField as PrimeField>::BigInt,
    pub power: u32,
    pub ceremony_power: u32,
}

impl<E: Pairing> FileHeader<E> {
    /// Create a new FileHeader instance by reading the section from the provided index
    pub fn new(file: &[u8], start: usize) -> Result<FileHeader<E>, String> {
        let min_size = start + (FileHeader::<E>::size() / 8) as usize;
        if file.len() < min_size {
            return Err("File too short to contain a valid header.".to_string());
        }

        let header_type = u32::from_le_bytes(
            file[start..start + 4]
                .try_into()
                .map_err(|_| "Failed to read header_type")?,
        );

        let header_length = u64::from_le_bytes(
            file[start + 4..start + 12]
                .try_into()
                .map_err(|_| "Failed to read header_length")?,
        );

        let field_size = u32::from_le_bytes(
            file[start + 12..start + 16]
                .try_into()
                .map_err(|_| "Failed to read field_size")?,
        );

        // Read q (field modulus, the next n bytes, where n = field_size)
        // Rounding up
        let modulus_size = ((E::BaseField::MODULUS_BIT_SIZE + 7) / 8) as usize;
        println!("Modulus Size Bits: {}", E::BaseField::MODULUS_BIT_SIZE);
        println!("Modulus Size: {}", modulus_size);
        let q_bytes = &file[start + 16..(start + 16 + modulus_size)];
        println!("Modulus Bytes: {:?}", q_bytes);
        let q = E::BaseField::from_le_bytes_mod_order(q_bytes);

        // Assert the modulus
        let modulus = E::BaseField::MODULUS;
        let mod_bn = E::BaseField::from_le_bytes_mod_order(&modulus.to_bytes_le());
        assert_eq!(q, mod_bn);

        // Read power (next 4 bytes, as a u32)
        let power = u32::from_le_bytes(
            file[(start + 16 + modulus_size)..(start + 20 + modulus_size)]
                .try_into()
                .map_err(|_| "Failed to read power")?,
        );

        // Read ceremony_power (next 4 bytes, as a u32)
        let ceremony_power = u32::from_le_bytes(
            file[(start + 20 + modulus_size)..(start + 24 + modulus_size)]
                .try_into()
                .map_err(|_| "Failed to read ceremony_power")?,
        );

        // Return the constructed FileHeader
        Ok(FileHeader {
            header_type,
            header_length,
            field_size,
            q: modulus,
            power,
            ceremony_power,
        })
    }

    /// Create a new FileHeader from a file
    pub fn new_from_file(file_data: &[u8]) -> Result<FileHeader<E>, String> {
        // Parse the file description
        let description =
            FileDescription::from_bytes(&file_data).expect("Failed to parse file description");

        // Find the section that contains the header
        if let Some(header_section) = description.sections.get(&1).and_then(|v| v.first()) {
            FileHeader::new(file_data, header_section.position as usize)
        } else {
            Err("No section found for the header.".to_string())
        }
    }

    /// Get the header size in bits
    pub fn size() -> u32 {
        // header_type, power, field_size, ceremony_power
        u32::BITS * 4
        // header_length (u64)
        + u64::BITS
        // BaseField size
        + E::BaseField::MODULUS_BIT_SIZE
    }
}

/// Curve Element Sizes
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurveElementSizes<E> {
    /// G1 Element Uncompressed Size
    g1_unc: usize,
    /// G1 Element Compressed Size
    g1_com: usize,
    /// G2 Element Uncompressed Size
    g2_unc: usize,
    /// G2 Element Compressed Size
    g2_com: usize,
    /// PhantomData
    _phantom: PhantomData<E>,
}

impl<E: Pairing> CurveElementSizes<E> {
    /// Create a new instance.
    pub fn new() -> CurveElementSizes<E> {
        let g1 = E::G1Affine::generator();
        let g1_unc = g1.serialized_size(Compress::No);
        let g1_com = g1.serialized_size(Compress::Yes);

        let g2 = E::G2Affine::generator();
        let g2_unc = g2.serialized_size(Compress::No);
        let g2_com = g2.serialized_size(Compress::Yes);

        CurveElementSizes {
            g1_unc,
            g1_com,
            g2_unc,
            g2_com,
            _phantom: PhantomData,
        }
    }

    /// Get the G1 Element Uncompressed Size
    pub fn g1_unc(&self) -> usize {
        self.g1_unc
    }

    /// Get the G1 Element Compressed Size
    pub fn g1_com(&self) -> usize {
        self.g1_com
    }

    /// Get the G2 Element Uncompressed Size
    pub fn g2_unc(&self) -> usize {
        self.g2_unc
    }

    /// Get the G2 Element Compressed Size
    pub fn g2_com(&self) -> usize {
        self.g2_com
    }
}

/// Powers of Tau
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PowersOfTau<E: Pairing> {
    /// Powers of tau in G1 - [tau^i]_1
    g1_pow: Vec<E::G1>,
    /// Powers of tau in G2 - [tau^i]_2
    g2_pow: Vec<E::G2>,
}

impl<E: Pairing> PowersOfTau<E> {
    /// Create a new instance from a file.
    pub fn new(filepath: &str) -> Self {
        let filepath = PathBuf::from(filepath);
        let file = FileLoader::new(filepath);
        let file_data = file.load().unwrap();
        let mut g1_pow: Vec<<E as Pairing>::G1> = Vec::new();
        let mut g2_pow: Vec<<E as Pairing>::G2> = Vec::new();

        // Get the header
        let header =
            FileHeader::<E>::new_from_file(&file_data).expect("Failed to parse FileHeader");

        // Get the file description to locate G1 and G2 sections
        let description =
            FileDescription::from_bytes(&file_data).expect("Failed to parse file description");

        // Read the sections for G1 and G2 powers (assuming section 2 for G1 and section 3 for G2)
        let g1_section: &FileSection = description.sections.get(&2).unwrap().first().unwrap();
        let g1_data_start = g1_section.position as usize;
        let g1_data_end = g1_data_start + g1_section.size as usize;
        let g1_data = &file_data[g1_data_start..g1_data_end];

        let g1_elements = (2u32.pow(header.power)) * 2 - 1;
        println!("G1 Elements: {}", g1_elements);
        let g2_elements = 2u32.pow(header.power);

        // g1 element sizes
        let g1 = E::G1Affine::generator();
        let g1_unc = g1.serialized_size(Compress::No);
        let g1_com = g1.serialized_size(Compress::Yes);

        // g2 element sizes
        let g2 = E::G2Affine::generator();
        let g2_unc = g2.serialized_size(Compress::No);
        let g2_com = g2.serialized_size(Compress::Yes);

        // Check if the data size corresponds to compressed or uncompressed G1 elements
        let element_size = g1_data.len() / g1_elements as usize;
        println!("G1 Element Size: {}", element_size);
        // Assert the size is either compressed or uncompressed
        assert!(element_size == g1_com || element_size == g1_unc);

        let compress = match element_size {
            x if x == g1_com => {
                println!("G1 is compressed");
                Compress::Yes
            }
            x if x == g1_unc => {
                println!("G1 is uncompressed");
                Compress::No
            }
            _ => panic!("Unexpected G1 element size."),
        };

        // Deserialize each G1 element
        let mut offset = 0;
        for _ in 0..g1_elements {
            // let g1_el: <E as Pairing>::BaseField =
            //     E::BaseField::from_le_bytes_mod_order(&g1_data[offset..]);
            // let g1_affine: <E as Pairing>::G1Affine = g1_el.into();
            let g1_affine =
                E::G1Affine::deserialize_with_mode(&g1_data[offset..], compress, Validate::No)
                    .expect("Failed to deserialize G1 element.");

            g1_pow.push(g1_affine.into());
            offset += element_size;
        }

        Self { g1_pow, g2_pow }
    }

    /// Get the powers of tau in G1
    pub fn g1_powers(&self) -> &[E::G1] {
        &self.g1_pow
    }

    /// Get the powers of tau in G2
    pub fn g2_powers(&self) -> &[E::G2] {
        &self.g2_pow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_bn254::Bn254;

    pub const PTAU_TEST_FILEPATH: &str = "ptau/ppot_0080_01.ptau.test";

    // Expected sizes for BLS12-381 and BN254
    // BLS12-381
    pub const BLS12_G1_COM_SIZE: usize = 48;
    pub const BLS12_G1_UNC_SIZE: usize = 96;
    pub const BLS12_G2_COM_SIZE: usize = 96;
    pub const BLS12_G2_UNC_SIZE: usize = 192;
    // BN254
    pub const BN256_G1_COM_SIZE: usize = 32;
    pub const BN256_G1_UNC_SIZE: usize = 64;
    pub const BN256_G2_COM_SIZE: usize = 64;
    pub const BN256_G2_UNC_SIZE: usize = 128;

    #[test]
    fn test_bls12_381_sizes() {
        let curve_sizes = CurveElementSizes::<Bls12_381>::new();

        assert_eq!(curve_sizes.g1_unc(), BLS12_G1_UNC_SIZE);
        assert_eq!(curve_sizes.g1_com(), BLS12_G1_COM_SIZE,);
        assert_eq!(curve_sizes.g2_unc(), BLS12_G2_UNC_SIZE,);
        assert_eq!(curve_sizes.g2_com(), BLS12_G2_COM_SIZE,);
    }

    #[test]
    fn test_bn254_sizes() {
        let curve_sizes = CurveElementSizes::<Bn254>::new();

        assert_eq!(curve_sizes.g1_unc(), BN256_G1_UNC_SIZE,);
        assert_eq!(curve_sizes.g1_com(), BN256_G1_COM_SIZE,);
        assert_eq!(curve_sizes.g2_unc(), BN256_G2_UNC_SIZE,);
        assert_eq!(curve_sizes.g2_com(), BN256_G2_COM_SIZE,);
    }

    #[test]
    fn test_file_description() {
        let test_setup = FileLoader::new(PathBuf::from(PTAU_TEST_FILEPATH));
        let file_data = test_setup.load().expect("Failed to load the setup file");

        let description = FileDescription::from_bytes(&file_data).unwrap();
        print!("{:#?}", description);

        let file_type = String::from(
            description
                .file_type
                .iter()
                .map(|&c| c as char)
                .collect::<String>(),
        );

        println!("File Type: {}", file_type);
    }

    #[test]
    fn test_file_header_bn254() {
        let setup_file = FileLoader::new(PathBuf::from(PTAU_TEST_FILEPATH));
        let file_data = setup_file.load().expect("Failed to load the setup file");

        let description =
            FileDescription::from_bytes(&file_data).expect("Failed to parse file description");

        // Find section 1 which is the header
        if let Some(header_section) = description.sections.get(&1).and_then(|v| v.first()) {
            let file_header: FileHeader<Bn254> =
                FileHeader::new(&file_data, header_section.position as usize)
                    .expect("Failed to parse FileHeader");

            println!("FileHeader size: {:#?}", FileHeader::<Bn254>::size());
            println!("FileHeader: {:#?}", file_header);
        } else {
            panic!("No section 1 found for the header!");
        }
    }

    #[test]
    fn test_powers_of_tau() {
        let setup_file = FileLoader::new(PathBuf::from(PTAU_TEST_FILEPATH));
        let file_data = setup_file.load().expect("Failed to load the setup file");

        let description =
            FileDescription::from_bytes(&file_data).expect("Failed to parse file description");

        println!("{:#?}", description);

        // Find section 1 which is the header
        if let Some(header_section) = description.sections.get(&1).and_then(|v| v.first()) {
            let file_header: FileHeader<Bn254> =
                FileHeader::new(&file_data, header_section.position as usize)
                    .expect("Failed to parse FileHeader");

            println!("FileHeader size: {:#?}", FileHeader::<Bn254>::size());
            println!("FileHeader: {:#?}", file_header);
        } else {
            panic!("No section 1 found for the header!");
        }

        let pot = PowersOfTau::<Bn254>::new(PTAU_TEST_FILEPATH);

        println!("{:?}", pot);

        assert!(!pot.g1_powers().is_empty(), "G1 powers are empty");
    }
}
