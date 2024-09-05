//! Fog of War

use ark_bls12_381::{
    g1::{G1_GENERATOR_X, G1_GENERATOR_Y},
    g2::{G2_GENERATOR_X, G2_GENERATOR_Y},
    Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use keaki::{kem::KEM, kzg::KZG, we::WE};
use rand::{seq::IteratorRandom, thread_rng};

pub const BOARD_SIZE: usize = 6;
pub const BOARD_TILES: usize = BOARD_SIZE * BOARD_SIZE;

// Starting Positions
// A - - - - -
// - - - - - -
// - - - - - -
// - - - - - -
// - - - - - -
// - - - - - B

const ALICE_STARTING_POS: usize = 0;
const BOB_STARTING_POS: usize = BOARD_TILES - 1;

/// Board
#[derive(Debug, Clone)]
pub struct Board {
    pub tiles: Vec<u8>,
}

impl Board {
    pub fn new() -> Self {
        Self {
            tiles: vec![0; BOARD_TILES],
        }
    }

    /// Returns all valid adjacent positions as indices of the `tiles` vector
    pub fn get_adjacent_positions(pos: u8) -> Vec<u8> {
        let row = pos as isize / BOARD_SIZE as isize;
        let col = pos as isize % BOARD_SIZE as isize;

        let deltas: [(isize, isize); 8] = [
            (-1, -1), // Top-left
            (-1, 0),  // Up
            (-1, 1),  // Top-right
            (0, -1),  // Left
            (0, 1),   // Right
            (1, -1),  // Bottom-left
            (1, 0),   // Down
            (1, 1),   // Bottom-right
        ];

        // Collect valid adjacent positions
        let mut valid_positions = Vec::new();
        for (drow, dcol) in deltas.iter() {
            let new_row = row + drow;
            let new_col = col + dcol;

            // Check if the new position is within vec bounds
            if new_row >= 0
                && new_row < BOARD_SIZE as isize
                && new_col >= 0
                && new_col < BOARD_SIZE as isize
            {
                let new_pos = (new_row * BOARD_SIZE as isize + new_col) as u8;
                valid_positions.push(new_pos);
            }
        }

        valid_positions
    }

    /// Returns a vec with 1s at the position and adjacent tiles, 0s elsewhere
    pub fn pos_to_vec_with_adj(pos: u8) -> Vec<u8> {
        let mut vec = vec![0; BOARD_TILES];

        // Set the current position to 1
        vec[pos as usize] = 1;

        // Get adjacent positions and set them to 1
        let adj_positions = Board::get_adjacent_positions(pos);
        for adj_pos in adj_positions {
            vec[adj_pos as usize] = 1;
        }

        vec
    }

    /// Returns a random adjacent position, if any
    pub fn get_random_adjacent_pos(pos: u8) -> Option<u8> {
        let adj_positions = Board::get_adjacent_positions(pos);
        adj_positions.into_iter().choose(&mut thread_rng())
    }

    /// Displays the current board, showing the player's position and the opponent's position if provided
    pub fn display(player_pos: u8, opponent_pos: Option<u8>, step: u32) {
        println!("\nStep {}: Current Player's View", step);

        for i in 0..BOARD_SIZE {
            for j in 0..BOARD_SIZE {
                let idx = (i * BOARD_SIZE + j) as u8;

                if idx == player_pos {
                    print!(" X "); // Current player's position
                } else if let Some(op_pos) = opponent_pos {
                    if idx == op_pos {
                        print!(" O ");
                    } else {
                        print!(" . ");
                    }
                } else {
                    print!(" . ");
                }
            }
            println!();
        }
    }
}

/// Game Struct
pub struct Game {
    // Extractable WE
    pub we: WE<Bls12_381>,
    // Alice's position
    pub alice_pos: u8,
    // Bob's position
    pub bob_pos: u8,
    // Alice's commitment
    pub alice_com: G1Projective,
    // Bob's commitment
    pub bob_com: G1Projective,
    // Encrypted Alice's position
    pub alice_enc_pos: Vec<(G2Projective, Vec<u8>)>,
    // Encrypted Bob's position
    pub bob_enc_pos: Vec<(G2Projective, Vec<u8>)>,
    // Current step
    pub step: u32,
    // Is game finished
    pub finished: bool,
}

impl Game {
    pub fn new(secret: Fr) -> Self {
        // Setup kzg
        let g1_generator = G1Affine::new(G1_GENERATOR_X, G1_GENERATOR_Y);
        let g2_generator = G2Affine::new(G2_GENERATOR_X, G2_GENERATOR_Y);
        let max_degree = BOARD_TILES;
        let kzg: KZG<Bls12_381> =
            KZG::setup(g1_generator.into(), g2_generator.into(), max_degree, secret);
        let kem: KEM<Bls12_381> = KEM::new(kzg);
        let we: WE<Bls12_381> = WE::new(kem);

        let alice_pos = ALICE_STARTING_POS as u8;
        println!("Alice's starting position: {}", alice_pos);
        let bob_pos = BOB_STARTING_POS as u8;
        println!("Bob's starting position: {}", bob_pos);

        // Get positional vectors
        let alice_pos_vec = Board::pos_to_vec_with_adj(alice_pos);
        println!("Alice's position vector: {:?}", alice_pos_vec);
        let bob_pos_vec = Board::pos_to_vec_with_adj(bob_pos);
        println!("Bob's position vector: {:?}", bob_pos_vec);

        // Construct polynomials for Alice and Bob positions
        let mut alice_pol = Vec::new();
        for value in alice_pos_vec.clone() {
            alice_pol.push(Fr::from(value as u32));
        }
        let mut bob_pol = Vec::new();
        for value in bob_pos_vec.clone() {
            bob_pol.push(Fr::from(value as u32));
        }

        // Commit to Alice and Bob's positions
        let alice_com = we.kem().kzg().commit(&alice_pol).unwrap();
        let bob_com = we.kem().kzg().commit(&bob_pol).unwrap();

        let mut alice_alphas = Vec::new();
        let mut bob_alphas = Vec::new();

        // Encrypt Alice and Bob's initial positions using the opponent's commitment
        for (index, val) in alice_pos_vec.iter().enumerate() {
            if *val == 1 {
                alice_alphas.push(Fr::from(index as u32));
            }
        }
        for (index, val) in bob_pos_vec.iter().enumerate() {
            if *val == 1 {
                bob_alphas.push(Fr::from(index as u32));
            }
        }

        let alice_enc_pos = we
            .encrypt(
                alice_com,
                alice_alphas.clone(),
                vec![Fr::from(1); alice_alphas.len()],
                &[0x01],
            )
            .unwrap();

        let bob_enc_pos = we
            .encrypt(
                bob_com,
                bob_alphas.clone(),
                vec![Fr::from(1); bob_alphas.len()],
                &[0x01],
            )
            .unwrap();

        Self {
            we,
            alice_pos,
            bob_pos,
            alice_com,
            bob_com,
            alice_enc_pos,
            bob_enc_pos,
            step: 0,
            finished: false,
        }
    }

    pub fn next(&mut self) -> () {
        // Check if the game is finished
        if self.finished {
            println!("Game is already finished.");
            return;
        }

        let is_alice_turn = self.step % 2 == 0;
        self.step += 1;

        // Get current player's and opponent's positions
        let (current_player_pos, opponent_pos) = if is_alice_turn {
            (self.alice_pos, self.bob_pos)
        } else {
            (self.bob_pos, self.alice_pos)
        };

        println!(
            "\nTurn {}: It's {}'s turn!",
            self.step,
            if is_alice_turn { "Alice" } else { "Bob" }
        );

        // Try to decrypt the opponent's position
        let opponent_visible = self.try_decrypt_opponent_position(is_alice_turn);

        // If decryption is successful, the current player wins
        if opponent_visible {
            Board::display(current_player_pos, Some(opponent_pos), self.step);

            if is_alice_turn {
                println!("Alice wins!");
            } else {
                println!("Bob wins!");
            }

            self.finished = true;
            return;
        } else {
            Board::display(current_player_pos, None, self.step);
        }

        // Move current player if decryption fails
        self.move_player(is_alice_turn);
    }

    /// Attempts to decrypt the opponent's position. Returns true if successful (opponent is visible).
    pub fn try_decrypt_opponent_position(&self, is_alice_turn: bool) -> bool {
        let (opponent_enc_pos, _, player_pos) = if is_alice_turn {
            (&self.bob_enc_pos, self.bob_com, self.alice_pos) // Alice trying to decrypt Bob's position
        } else {
            (&self.alice_enc_pos, self.alice_com, self.bob_pos) // Bob trying to decrypt Alice's position
        };

        // Try to decrypt with every opening.
        let player_pos_vec = Board::pos_to_vec_with_adj(player_pos);
        let mut player_pol = Vec::new();
        for value in player_pos_vec.clone() {
            player_pol.push(Fr::from(value as u32));
        }

        // Open the polynomial at the player's positions
        let mut proofs = Vec::new();
        for (index, &value) in player_pos_vec.iter().enumerate() {
            if value == 1 {
                let proof = self
                    .we
                    .kem()
                    .kzg()
                    .open(&player_pol, &Fr::from(index as u32))
                    .unwrap();
                proofs.push(proof);
            }
        }

        for proof in proofs {
            for (key_ct, msg_ct) in opponent_enc_pos.iter() {
                let msg = self.we.decrypt_single(proof, *key_ct, msg_ct).unwrap();

                if msg == [0x01] {
                    println!("Decryption successful! Opponent's position is visible.");
                    return true;
                }
            }
        }

        return false;
    }

    /// Moves the current player to a random adjacent position.
    pub fn move_player(&mut self, is_alice_turn: bool) {
        let (_, opponent_com, player_pos) = if is_alice_turn {
            (&self.bob_enc_pos, self.bob_com, self.alice_pos)
        } else {
            (&self.alice_enc_pos, self.alice_com, self.bob_pos)
        };

        // Get a random adjacent position
        if let Some(new_pos) = Board::get_random_adjacent_pos(player_pos) {
            // Get vector representation of the new position
            let player_pos_vec = Board::pos_to_vec_with_adj(new_pos);
            let mut player_pol = Vec::new();
            for value in player_pos_vec.clone() {
                player_pol.push(Fr::from(value as u32));
            }

            // Commit to the new position
            let player_com = self.we.kem().kzg().commit(&player_pol).unwrap();

            // Prepare alphas for encryption (indices where player position is 1)
            let mut player_alphas = Vec::new();
            for (index, val) in player_pos_vec.iter().enumerate() {
                if *val == 1 {
                    player_alphas.push(Fr::from(index as u32));
                }
            }

            // Encrypt the new position vector using the opponent's commitment
            let enc_pos = self
                .we
                .encrypt(
                    opponent_com,
                    player_alphas.clone(),
                    vec![Fr::from(1); player_alphas.len()],
                    &[0x01],
                )
                .unwrap();

            // Update the player's encrypted position and commitment
            if is_alice_turn {
                self.alice_enc_pos = enc_pos;
                self.alice_com = player_com;
                self.alice_pos = new_pos;
            } else {
                self.bob_enc_pos = enc_pos;
                self.bob_com = player_com;
                self.bob_pos = new_pos;
            }
        } else {
            println!("No valid moves available.");
        }
    }
}

#[cfg(test)]
mod fow_tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_fog_of_war_game() {
        // Setup secret
        let rng = &mut test_rng();
        let secret = Fr::rand(rng);

        // Initialize the game
        let mut game = Game::new(secret);

        // Simulate a few turns
        while !game.finished {
            game.next();
        }

        assert!(true);
    }
}
