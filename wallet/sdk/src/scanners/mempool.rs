use nyks_standards::wallet::keys::viewing_key::ViewingKey;

pub struct MempoolScanner {
    keys: Vec<ViewingKey>,
}

impl MempoolScanner {
    pub fn new(keys: Vec<ViewingKey>) -> Self {
        MempoolScanner { keys }
    }

    pub fn add_key(&mut self, key: ViewingKey) {
        self.keys.push(key);
    }
}
