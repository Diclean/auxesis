//! Stable ids for the data paths in the coverage matrix
//! (`docs/phase1.md` §2).

use std::str::FromStr;

/// Declares [`PathId`] from one list of matrix row ids, so the enum,
/// [`PathId::ALL`] and [`PathId::as_str`] cannot drift apart.
macro_rules! path_ids {
    ($($row:ident),+ $(,)?) => {
        /// One data path from the coverage matrix. The variant name is the
        /// row id (`A1`, `B5`, ...). Ids are never renumbered.
        #[non_exhaustive]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum PathId {
            $($row,)+
        }

        impl PathId {
            /// Every path, in matrix order. The registry test checks that each
            /// one has exactly one row.
            pub const ALL: &'static [PathId] = &[$(PathId::$row),+];

            /// The matrix row id, e.g. `"B5"`.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(PathId::$row => stringify!($row),)+
                }
            }
        }
    };
}

path_ids! {
    A1, A2, A3,
    B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15, B16, B17, B18,
    B19, B20, B21, B22, B23,
    C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12,
    D1, D2, D3, D4,
    E1, E2,
    F1, F2,
    G1, G2, G3, G4, G5, G6, G7,
    H1,
    I1, I2,
}

/// An id that names no path in the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no privacy path has this id")]
pub struct UnknownPath;

impl FromStr for PathId {
    type Err = UnknownPath;

    /// Parses a matrix row id. Unknown ids cannot become a [`PathId`], so
    /// they cannot be admitted at all.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PathId::ALL
            .iter()
            .copied()
            .find(|id| id.as_str() == s)
            .ok_or(UnknownPath)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_each_matrix_row_once() {
        // 49 rows before K16, plus B19 to B22, the owner profile row B23 and the
        // iMessage private-mode notice C11 and the held-answers display C12.
        assert_eq!(PathId::ALL.len(), 56);
        let mut ids: Vec<&str> = PathId::ALL.iter().map(|id| id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 56);
    }

    #[test]
    fn ids_round_trip_and_unknown_ids_do_not_parse() {
        for id in PathId::ALL {
            assert_eq!(id.as_str().parse::<PathId>(), Ok(*id));
        }
        assert_eq!("Z9".parse::<PathId>(), Err(UnknownPath));
        assert_eq!("a1".parse::<PathId>(), Err(UnknownPath));
        assert_eq!("".parse::<PathId>(), Err(UnknownPath));
    }

    #[test]
    fn k16_rows_spell_their_matrix_ids() {
        assert_eq!(PathId::B19.as_str(), "B19");
        assert_eq!(PathId::B20.as_str(), "B20");
        assert_eq!(PathId::B21.as_str(), "B21");
        assert_eq!(PathId::B22.as_str(), "B22");
        assert_eq!("B22".parse::<PathId>(), Ok(PathId::B22));
    }
}
