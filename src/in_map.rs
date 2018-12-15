use std::cmp;
use std::collections::HashMap;
use std::hash;

pub trait LazyView<K: Copy + hash::Hash + cmp::Eq, V> {
    fn lazy_view(&mut self, key: K) -> Option<MapBorrow<K, V>>;
    fn lazy_view_or_insert_with<F>(&mut self, key: K, default: F) -> MapBorrow<K, V>
    where
        F: FnOnce() -> V;
}

impl<K: Copy + hash::Hash + cmp::Eq, V> LazyView<K, V> for HashMap<K, V> {
    fn lazy_view(&mut self, key: K) -> Option<MapBorrow<K, V>> {
        if self.contains_key(&key) {
            Some(MapBorrow { inner: self, key })
        } else {
            None
        }
    }

    fn lazy_view_or_insert_with<F>(&mut self, key: K, default: F) -> MapBorrow<K, V>
    where
        F: FnOnce() -> V,
    {
        self.entry(key).or_insert_with(default);
        self.lazy_view(key).unwrap()
    }
}

pub struct MapBorrow<'m, K: hash::Hash + cmp::Eq, V> {
    inner: &'m mut HashMap<K, V>,
    key: K,
}

impl<'m, K: hash::Hash + cmp::Eq, V> AsRef<V> for MapBorrow<'m, K, V> {
    fn as_ref(&self) -> &V {
        self.inner.get(&self.key).expect("checked at construction")
    }
}

impl<'m, K: hash::Hash + cmp::Eq, V> AsMut<V> for MapBorrow<'m, K, V> {
    fn as_mut(&mut self) -> &mut V {
        self.inner
            .get_mut(&self.key)
            .expect("checked at construction")
    }
}

impl<'m, K: hash::Hash + cmp::Eq, V> MapBorrow<'m, K, V> {
    pub fn view(&self) -> &HashMap<K, V> {
        &self.inner
    }
}
