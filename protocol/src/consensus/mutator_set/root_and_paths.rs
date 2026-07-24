use tasm_lib::prelude::Digest;

#[derive(Debug, Clone, Default)]
pub struct RootAndPaths {
    pub root: Digest,
    pub paths: Vec<Vec<Digest>>,
}
