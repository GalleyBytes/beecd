use anyhow::{anyhow, Result};
use serde::Deserialize;
use serde_json::{json, Map};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
enum DocumentError {
    #[error("Value of `{0}` is not a string")]
    NotAString(String),

    #[error("Document is not a JSON Object: `{0}`")]
    NotAnObject(String),

    #[error("`{0}` missing in resource")]
    MissingData(String),

    #[error("Missing a document to compare")]
    MissingDocument,

    #[error("Missing a side to compare")]
    MissingSideToCompare,
}

/// Compare two Kubernetes manifets (either JSON to YAML formatted).
#[derive(Default, Debug, Clone, PartialEq)]
pub struct Diff {
    diff_items: Vec<DiffItem>,
    left: Option<serde_json::Value>,
    right: Option<serde_json::Value>,
    field_set: Option<serde_json::Value>,
    ignore_set: Option<serde_json::Value>,
}

impl Diff {
    /// Where `left` is being diffed into, and `right` is the document with the changes.
    ///
    /// The `field_set` is a set of managedFields generally sent from the k8s-api server
    /// when requesting resource data. This field is used to omit certain fields (or
    /// only do a diff on some fields) between the left and the right documents.
    pub fn new(
        left: Option<serde_json::Value>,
        right: Option<serde_json::Value>,
        field_set: Option<serde_json::Value>,
        ignore_set: Option<serde_json::Value>,
    ) -> Diff {
        Diff {
            left,
            right,
            field_set,
            ignore_set,
            diff_items: Vec::new(),
        }
    }

    pub fn ordered_changes(&self) -> Vec<String> {
        self.diff_items
            .iter()
            .filter(|item| item.status != Status::NoChange)
            .map(|item| {
                let (prefix, parent) = if item.status == Status::Added {
                    ("+", item.parent_path(">>"))
                } else if item.status == Status::Removed {
                    ("-", item.parent_path(">>"))
                } else if item.status == Status::Updated {
                    ("^", item.parent_path(">>"))
                } else {
                    ("!", item.parent_path(">>"))
                };
                format!("{}{}", prefix, parent)
            })
            .collect::<Vec<_>>()
    }

    /// After running `.do_compare()`, results can be return as a String.
    ///
    ///
    /// The text is a yaml-like diff string that is ready to be printed to the screen.
    /// Colors also used along with +/- signs. + Indicates added elements caused by
    /// the right-hand-side document. - indicates missing elements from the right-hand-side
    /// document. ASNI coloring is used to display to a terminal.
    pub fn text(&self, as_manifest: bool) -> String {
        let mut output = String::new();
        for item in &self.diff_items {
            let s = item.to_yaml(as_manifest);

            info!(?item, s);

            if s == String::new() {
                continue;
            }
            if output.is_empty() {
                output = s;
                continue;
            }
            output = format!("{}\n{}", output, s);
        }
        output
    }

    /// After running `.do_compare()`, calling `.print()` prints the resulting diff to stdout.
    ///
    /// Formatting is the exact same as [Diff::text].
    pub fn print(&self) {
        for item in &self.diff_items {
            let s = item.to_yaml(false);
            if s == String::new() {
                continue;
            }
            println!("{}", s);
        }
    }

    /// Sets the status of any objects or arrays with no children as "Removed"
    /// Also set empty parents that are added in the RHS as the empty type to force it to show up in the manifest
    pub fn remove_childrenless_parents(&mut self) {
        #[derive(Debug, Clone)]
        struct ParentItem {
            index: usize,
            children: i32,
            status: Status,
        }

        let mut parents: HashMap<String, ParentItem> = HashMap::new();
        let sep = "~";
        let total_items = self.diff_items.len();

        for (i, item) in self.diff_items.iter_mut().rev().enumerate() {
            let index = total_items - i - 1;
            let parent = item.parent_path(sep);
            if item.value.is_none() {
                match parents.get_mut(&parent) {
                    Some(_) => {}
                    None => {
                        parents.insert(
                            parent,
                            ParentItem {
                                index,
                                children: 0,
                                status: item.status.clone(),
                            },
                        );
                    }
                }
                continue;
            }
            if item.status == Status::Removed {
                continue;
            }

            match parents.get_mut(&parent) {
                Some(c) => {
                    c.children += 1;
                }
                None => {
                    parents.insert(
                        parent,
                        ParentItem {
                            index,
                            children: 1,
                            status: item.status.clone(),
                        },
                    );
                }
            }
        }

        let highest_order = parents.iter().fold(0, |acc, p| acc.max(dots(p.0, sep)));

        for i in (1..=highest_order).rev() {
            let ordered_parents_clone = parents.clone();
            let parents_of_higher_order = ordered_parents_clone
                .iter()
                .filter(|p| dots(p.0, sep) == i)
                .collect::<Vec<_>>();

            for (parent, item) in parents.iter_mut().filter(|p| dots(p.0, sep) == i - 1) {
                for (higher_order_parent, higher_order_parent_item) in
                    parents_of_higher_order.iter()
                {
                    let mut parts = higher_order_parent.split(sep).collect::<Vec<_>>();
                    parts.pop();
                    let of_parent = parts.join(sep);

                    if *parent == of_parent && higher_order_parent_item.children > 0 {
                        item.children += 1;
                    }
                }
            }
        }

        debug!("{:#?}", parents);

        for (_, item) in parents {
            if let Some(d) = self.diff_items.get_mut(item.index) {
                info!("{:?}", d);
                let is_added = matches!(item.status, Status::Added);

                let value_type = match &d.metadata {
                    Some(m) => m.value_type.clone(),
                    None => String::new(),
                };

                if !is_added && item.children == 0 {
                    d.status = Status::Removed
                }

                if item.children == 0 && is_added && value_type == "array" {
                    d.value = Some(json!([]))
                } else if item.children == 0 && is_added && value_type == "object" {
                    d.value = Some(json!({}))
                }
            }
        }
    }

    /// Usually the first function to call after [Diff::new]. `.do_compare()` runs the comparison
    /// between the left/right-hand-side documents.
    ///
    /// After running this method, see result with either [Diff::text] or [Diff::print].
    pub fn do_compare(&mut self) -> Result<()> {
        let mut parent: Vec<Key> = Vec::new();
        // Take ownership to avoid the borrow checker issue with self-referential borrows
        let left = std::mem::take(&mut self.left);
        let right = std::mem::take(&mut self.right);
        let field_set = std::mem::take(&mut self.field_set);
        let ignore_set = std::mem::take(&mut self.ignore_set);

        let result = self.compare(
            left.as_ref(),
            right.as_ref(),
            field_set.as_ref(),
            ignore_set.as_ref(),
            &mut parent,
        );

        // Restore the values
        self.left = left;
        self.right = right;
        self.field_set = field_set;
        self.ignore_set = ignore_set;

        result
    }

    /// After running the comparison, check if anything was changed.
    /// `true` means differences were found.
    pub fn is_diff(&self) -> bool {
        self.diff_items
            .iter()
            .any(|item| item.status != Status::NoChange)
    }

    fn compare(
        &mut self,
        left: Option<&serde_json::Value>,
        right: Option<&serde_json::Value>,
        field_set: Option<&serde_json::Value>,
        ignore_set: Option<&serde_json::Value>,
        parent: &mut [Key],
    ) -> Result<()> {
        if left.is_some() & right.is_none() {
            self.diff_items.push(DiffItem {
                key: Key::StringKey(String::from(".")),
                parent: parent.to_vec(),
                value: None,
                status: Status::Removed,
                metadata: None,
            });

            return Err(anyhow!(DocumentError::MissingSideToCompare));
            // return Ok(());
        }

        if let (Some(l_value), Some(r_value)) = (left, right) {
            if (l_value.is_array() && !r_value.is_array())
                || (l_value.is_object() && !r_value.is_object())
                || (l_value.is_string() && !r_value.is_string())
                || (l_value.is_number() && !r_value.is_number())
                || (l_value.is_boolean() && !r_value.is_boolean())
                || (l_value.is_null() && !r_value.is_null())
            {
                warn!("type mismatch {:?} {:?}", l_value, r_value);
                // In this case, remove the old and replace 100% with the new
                return Ok(());
            }

            if l_value.is_array() {
                // Means value is array
                let l_array = l_value.as_array().unwrap();
                let r_array = r_value.as_array().unwrap();
                self.diff_array(l_array, r_array, field_set, ignore_set, parent)?;
            } else if l_value.is_object() {
                let l_object = l_value.as_object().unwrap();
                let r_object = r_value.as_object().unwrap();
                self.diff_object(l_object, r_object, field_set, ignore_set, parent)?;
            } else {
                // info!(?r_value);
            }
        }
        Ok(())
    }

    fn diff_array(
        &mut self,
        l_array: &[serde_json::Value],
        r_array: &[serde_json::Value],
        field_set: Option<&serde_json::Value>,
        ignore_set: Option<&serde_json::Value>,
        parent: &mut [Key],
    ) -> Result<()> {
        let r_array_len = r_array.len();
        let l_array_len = l_array.len();
        let mut first_iter_flag = true;
        for index in 0..l_array_len {
            let l_item = &l_array[index];
            let l_json_type = get_value_type(l_item);

            if index + 1 > r_array_len {
                info!(
                    "removing value {:?} from the output since its missing on the right",
                    l_array[index]
                );
                self.diff_items.push(DiffItem {
                    key: Key::Index(index),
                    parent: parent.to_vec(),
                    value: Some(l_array[index].clone()),
                    status: Status::Removed,
                    metadata: Some(Metadata {
                        first_in_iter: first_iter_flag,
                        value_type: get_value_type(&l_array[index]),
                    }),
                });
                first_iter_flag = false;
            } else {
                let r_item = &r_array[index];
                info!(
                    "adding value {:?} for some reason where l_item is {:?} ,{}",
                    r_item,
                    l_item,
                    r_item == l_item
                );
                if r_item.is_object() || r_item.is_array() {
                    let value_opt = value_option_for_empty_object_or_array(r_item);

                    self.diff_items.push(DiffItem {
                        key: Key::Index(index),
                        parent: parent.to_vec(),
                        value: value_opt,
                        status: Status::NoChange,
                        metadata: Some(Metadata {
                            first_in_iter: first_iter_flag,
                            value_type: get_value_type(r_item),
                        }),
                    });
                    first_iter_flag = false;
                    let mut parent = parent.to_owned();
                    parent.push(Key::Index(index));
                    self.compare(
                        Some(l_item),
                        Some(r_item),
                        field_set,
                        ignore_set,
                        &mut parent,
                    )?;
                } else {
                    let r_json_type = get_value_type(r_item);

                    if l_json_type != r_json_type || *r_item != *l_item {
                        // Mismatched types again, replace with new || changed data
                        self.diff_items.push(DiffItem {
                            key: Key::Index(index),
                            parent: parent.to_vec(),
                            value: Some(l_item.clone()),
                            status: Status::Removed,
                            metadata: Some(Metadata {
                                first_in_iter: first_iter_flag,
                                value_type: get_value_type(l_item),
                            }),
                        });

                        self.diff_items.push(DiffItem {
                            key: Key::Index(index),
                            parent: parent.to_vec(),
                            value: Some(r_item.clone()),
                            status: Status::Updated,
                            metadata: Some(Metadata {
                                first_in_iter: first_iter_flag,
                                value_type: get_value_type(r_item),
                            }),
                        });
                        first_iter_flag = false;
                    } else {
                        // No changes
                        self.diff_items.push(DiffItem {
                            key: Key::Index(index),
                            parent: parent.to_vec(),
                            value: Some(r_item.clone()),
                            status: Status::NoChange,
                            metadata: Some(Metadata {
                                first_in_iter: first_iter_flag,
                                value_type: get_value_type(r_item),
                            }),
                        });
                        first_iter_flag = false;
                    }

                    // info!(?r_item);
                }
            }
        }
        if r_array_len > l_array_len {
            info!(
                "r_array is bigger than l_array ({}>{})",
                r_array_len, l_array_len
            );

            first_iter_flag = true;

            for (index, _) in r_array
                .iter()
                .enumerate()
                .take(r_array_len)
                .skip(l_array_len)
            {
                // for index in l_array_len..r_array_len {
                // println!("Hello");
                // info!(index);

                // This is a brand spanking new object. If the value is an object or array, iterate. Else add each as new with proper key.
                if r_array[index].is_array() || r_array[index].is_object() {
                    let value_opt = value_option_for_empty_object_or_array(&r_array[index]);

                    self.diff_items.push(DiffItem {
                        key: Key::Index(index),
                        parent: parent.to_vec(),
                        value: value_opt,
                        status: Status::Added,
                        metadata: Some(Metadata {
                            first_in_iter: first_iter_flag,
                            value_type: get_value_type(&r_array[index]),
                        }),
                    });
                    first_iter_flag = false;
                    let mut parent = parent.to_owned();
                    parent.push(Key::Index(index));

                    let no_left = if r_array[index].is_array() {
                        serde_json::json!([])
                    } else {
                        serde_json::json!({})
                    };

                    self.compare(
                        Some(&no_left),
                        Some(&r_array[index]),
                        None,
                        None,
                        &mut parent,
                    )?;
                    // Do something cool
                } else {
                    self.diff_items.push(DiffItem {
                        key: Key::Index(index),
                        parent: parent.to_vec(),
                        value: Some(r_array[index].clone()),
                        status: Status::Added,
                        metadata: Some(Metadata {
                            first_in_iter: first_iter_flag,
                            value_type: get_value_type(&r_array[index]),
                        }),
                    });
                    first_iter_flag = false;
                }
            }
        }
        Ok(())
    }

    fn diff_object(
        &mut self,
        l_object: &Map<String, serde_json::Value>,
        r_object: &Map<String, serde_json::Value>,
        field_set: Option<&serde_json::Value>,
        ignore_set: Option<&serde_json::Value>,
        parent: &mut [Key],
    ) -> Result<()> {
        let mut first_iter_flag = true;
        let mut reset_first_iter_flag = true;
        for (k, l_item) in l_object {
            let is_index_parent = match parent.last() {
                Some(p) => matches!(p, Key::Index(_i)),
                None => false,
            };
            let new_field_set = match field_set {
                None => None,
                Some(fs) => {
                    check_field_set(Key::StringKey(k.to_string()), is_index_parent, fs, l_object)
                }
            };

            let new_ignore_set = match ignore_set {
                None => None,
                Some(fs) => {
                    check_ignore_set(Key::StringKey(k.to_string()), is_index_parent, fs, l_object)
                }
            };

            let is_ignored = match new_ignore_set.as_ref() {
                Some(s) => match s.as_object() {
                    Some(ignore_set) => ignore_set.contains_key("!"),
                    None => false,
                },
                None => false,
            };

            let is_managed = match new_field_set.as_ref() {
                Some(s) => match s.as_object() {
                    Some(s) => !s.contains_key("!"),
                    None => {
                        return Err(anyhow!(DocumentError::NotAnObject(format!("{:?}", s),)));
                    }
                },
                None => true,
            };

            debug!(
                "{} {} managed and {} ignored",
                pretty_key(parent.to_vec(), k.to_string()),
                if is_managed { "is" } else { "is not" },
                if is_ignored { "is" } else { "is not" }
            );

            // Special cases where r_object needs to be mutable include when
            // r_object does not have the key 'k', but checking the contents
            // of the r_object[k] is required. For example, r_object[k] might
            // include data that should be ignored. If r_object[k] does not
            // exist, then that data will be removed.
            //
            // We only clone when we need to modify - track whether we need the modified version
            let needs_insert = !r_object.contains_key(k) && !is_ignored && l_item.is_object();
            let r_object_modified: Option<Map<String, serde_json::Value>>;
            let r_object_ref: &Map<String, serde_json::Value> = if needs_insert {
                let mut modified = r_object.clone();
                modified.insert(k.to_string(), json!({}));
                r_object_modified = Some(modified);
                r_object_modified.as_ref().unwrap()
            } else {
                r_object
            };

            let l_json_type = get_value_type(l_item);
            if !is_managed || is_ignored {
                self.diff_items.push(DiffItem {
                    key: Key::StringKey(k.to_string()),
                    parent: parent.to_vec(),
                    value: Some(l_item.clone()),
                    status: Status::NoChange,
                    metadata: Some(Metadata {
                        first_in_iter: first_iter_flag,
                        value_type: get_value_type(l_item),
                    }),
                });
                first_iter_flag = false;
                reset_first_iter_flag = false;
            } else if !r_object_ref.contains_key(k) {
                self.diff_items.push(DiffItem {
                    key: Key::StringKey(k.to_string()),
                    parent: parent.to_vec(),
                    value: Some(l_item.clone()),
                    status: Status::Removed,
                    metadata: Some(Metadata {
                        first_in_iter: first_iter_flag,
                        value_type: get_value_type(l_item),
                    }),
                });
            } else {
                let r_item = &r_object_ref[k];
                if l_item.is_object() || l_item.is_array() {
                    let left_value_opt = value_option_for_empty_object_or_array(l_item);
                    let right_value_opt = value_option_for_empty_object_or_array(r_item);

                    let value_opt = if left_value_opt.is_some() && right_value_opt.is_some() {
                        left_value_opt
                    } else {
                        None
                    };

                    self.diff_items.push(DiffItem {
                        key: Key::StringKey(k.to_string()),
                        parent: parent.to_vec(),
                        value: value_opt,
                        status: Status::NoChange,
                        metadata: Some(Metadata {
                            first_in_iter: first_iter_flag,
                            value_type: get_value_type(l_item),
                        }),
                    });
                    first_iter_flag = false;
                    reset_first_iter_flag = false;
                    let mut parent = parent.to_owned();
                    parent.push(Key::StringKey(k.to_string()));
                    self.compare(
                        Some(l_item),
                        Some(r_item),
                        new_field_set.as_ref(),
                        new_ignore_set.as_ref(),
                        &mut parent,
                    )?;
                } else {
                    let r_json_type = get_value_type(r_item);
                    if l_json_type != r_json_type {
                        // Mismatched types again, replace with new
                        self.diff_items.push(DiffItem {
                            key: Key::StringKey(k.to_string()),
                            parent: parent.to_vec(),
                            value: Some(l_item.clone()),
                            status: Status::Removed,
                            metadata: Some(Metadata {
                                first_in_iter: first_iter_flag,
                                value_type: get_value_type(l_item),
                            }),
                        });
                        if reset_first_iter_flag {
                            first_iter_flag = true
                        }

                        self.diff_items.push(DiffItem {
                            key: Key::StringKey(k.to_string()),
                            parent: parent.to_vec(),
                            value: Some(r_item.clone()),
                            status: Status::Updated,
                            metadata: Some(Metadata {
                                first_in_iter: first_iter_flag,
                                value_type: get_value_type(r_item),
                            }),
                        });
                        first_iter_flag = false;
                        reset_first_iter_flag = false;
                    } else if *r_item != *l_item {
                        self.diff_items.push(DiffItem {
                            key: Key::StringKey(k.to_string()),
                            parent: parent.to_vec(),
                            value: Some(l_item.clone()),
                            status: Status::Removed,
                            metadata: Some(Metadata {
                                first_in_iter: first_iter_flag,
                                value_type: get_value_type(l_item),
                            }),
                        });
                        if reset_first_iter_flag {
                            first_iter_flag = true
                        }

                        self.diff_items.push(DiffItem {
                            key: Key::StringKey(k.to_string()),
                            parent: parent.to_vec(),
                            value: Some(r_item.clone()),
                            status: Status::Updated,
                            metadata: Some(Metadata {
                                first_in_iter: first_iter_flag,
                                value_type: get_value_type(r_item),
                            }),
                        });
                        first_iter_flag = false;
                        reset_first_iter_flag = false;
                    } else {
                        self.diff_items.push(DiffItem {
                            key: Key::StringKey(k.to_string()),
                            parent: parent.to_vec(),
                            value: Some(r_item.clone()),
                            status: Status::NoChange,
                            metadata: Some(Metadata {
                                first_in_iter: first_iter_flag,
                                value_type: get_value_type(r_item),
                            }),
                        });
                        first_iter_flag = false;
                        reset_first_iter_flag = false;
                    }
                }
            }
        }
        if reset_first_iter_flag {
            first_iter_flag = true;
        }
        for (k, r_item) in r_object {
            if l_object.contains_key(k) {
                continue;
            }

            // This is a brand spanking new object. If the value is an object or array, iterate. Else add each as new with proper key.
            if r_item.is_array() || r_item.is_object() {
                let value_opt = value_option_for_empty_object_or_array(r_item);

                self.diff_items.push(DiffItem {
                    key: Key::StringKey(k.to_string()),
                    parent: parent.to_vec(),
                    value: value_opt,
                    status: Status::Added,
                    metadata: Some(Metadata {
                        first_in_iter: first_iter_flag,
                        value_type: get_value_type(r_item),
                    }),
                });
                first_iter_flag = false;
                let mut parent = parent.to_owned();
                parent.push(Key::StringKey(k.to_string()));

                let no_left = if r_item.is_array() {
                    serde_json::json!([])
                } else {
                    serde_json::json!({})
                };

                self.compare(Some(&no_left), Some(r_item), None, None, &mut parent)?;
            } else {
                self.diff_items.push(DiffItem {
                    key: Key::StringKey(k.to_string()),
                    parent: parent.to_vec(),
                    value: Some(r_item.clone()),
                    status: Status::Added,
                    metadata: Some(Metadata {
                        first_in_iter: first_iter_flag,
                        value_type: get_value_type(r_item),
                    }),
                });
                first_iter_flag = false;
            }
        }
        Ok(())
    }
}

fn pretty_key(parent: Vec<Key>, key: String) -> String {
    let prefix = parent
        .iter()
        .map(|key| match key {
            Key::StringKey(s) => {
                if s.contains('.') {
                    format!("[{}]", s)
                } else {
                    s.clone()
                }
            }
            Key::Index(i) => format!("{}", i),
        })
        .collect::<Vec<_>>()
        .join(".");

    let fmt_key = if key.contains('.') {
        format!("[{}]", key)
    } else {
        key
    };

    format!("{}.{}", prefix, fmt_key)
}

#[derive(Debug, Default, Clone, PartialEq)]
struct DiffItem {
    key: Key,
    parent: Vec<Key>,
    value: Option<serde_json::Value>,
    status: Status,
    metadata: Option<Metadata>,
}

impl DiffItem {
    fn parent_path(&self, sep: &str) -> String {
        let path = self
            .parent
            .iter()
            .map(Key::to_string)
            .collect::<Vec<_>>()
            .join(sep);
        let leading_dot = if path.is_empty() { "" } else { sep };
        let child_key = self.key.to_string();
        format!("{}{}{}{}", leading_dot, path, sep, child_key)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Metadata {
    first_in_iter: bool,
    value_type: String,
}

#[derive(Debug, Clone, PartialEq)]
enum Key {
    StringKey(String),
    Index(usize),
}

impl Default for Key {
    fn default() -> Self {
        Key::Index(0)
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::StringKey(s) => write!(f, "{}", s),
            Key::Index(i) => write!(f, "{}", i),
        }
    }
}

fn dots(s: &str, sep: &str) -> i32 {
    s.split(sep).fold(-1, |acc, _| acc + 1)
}

#[derive(Debug, PartialEq, Clone, Default)]
enum Status {
    Added,
    Removed,
    Updated,
    #[default]
    NoChange,
}

trait ToYaml {
    fn to_yaml(&self, _: bool) -> String;
}

impl ToYaml for DiffItem {
    fn to_yaml(&self, as_manifest: bool) -> String {
        let (pre, reset) = if as_manifest {
            (
                match self.status {
                    Status::Added => " ",
                    Status::Removed => return String::new(),
                    Status::Updated => " ",
                    Status::NoChange => " ",
                },
                String::new(),
            )
        } else {
            (
                match self.status {
                    Status::Added => "\x1b[32m+",
                    Status::Removed => "\x1b[31m-",
                    Status::Updated => "\x1b[32m+",
                    Status::NoChange => "\x1b[0m ",
                },
                String::from("\x1b[0m"),
            )
        };
        let mut indent_level = self.parent.len();

        let is_parent_an_index = match self.parent.last() {
            Some(k) => match k {
                Key::StringKey(_s) => false,
                Key::Index(_i) => true,
            },
            None => false,
        };

        if is_parent_an_index {
            indent_level -= 1;
        }
        // trace!("{:#?}", self);

        match &self.key {
            Key::StringKey(s) => {
                let value = match &self.value {
                    Some(s) => s.to_string(),
                    None => String::new(),
                };
                match &self.metadata {
                    Some(m) => {
                        if is_parent_an_index && m.first_in_iter {
                            format!(
                                "{} {}- {}: {}{}",
                                pre,
                                "  ".repeat(indent_level - 1),
                                s,
                                value,
                                reset
                            )
                        } else {
                            format!(
                                "{} {}{}: {}{}",
                                pre,
                                "  ".repeat(indent_level),
                                s,
                                value,
                                reset
                            )
                        }
                    }
                    None => format!(
                        "{} {}{}: {}{}",
                        pre,
                        "  ".repeat(indent_level),
                        s,
                        value,
                        reset
                    ),
                }
            }
            Key::Index(_i) => match &self.value {
                Some(s) => match &self.metadata {
                    Some(m) => {
                        if is_parent_an_index && m.first_in_iter {
                            format!(
                                "{} {}- - {}{}",
                                pre,
                                "  ".repeat(indent_level - 1),
                                s,
                                reset
                            )
                        } else if is_parent_an_index {
                            format!(
                                "{} {}  - {}{}",
                                pre,
                                "  ".repeat(indent_level - 1),
                                s,
                                reset
                            )
                        } else {
                            format!("{} {}- {}{}", pre, "  ".repeat(indent_level - 1), s, reset)
                        }
                    }
                    None => format!("{} {}- {}{}", pre, "  ".repeat(indent_level - 1), s, reset),
                },
                None => String::new(),
            },
        }
    }
}

fn get_value_type(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(_) => "boolean".to_string(),
        serde_json::Value::Number(_) => "number".to_string(),
        serde_json::Value::String(_) => "string".to_string(),
        serde_json::Value::Array(_) => "array".to_string(),
        serde_json::Value::Object(_) => "object".to_string(),
    }
}

fn check_position<'a>(
    at_map: &'a Map<String, serde_json::Value>,
    data_object: &Map<String, serde_json::Value>,
) -> Option<&'a serde_json::Value> {
    let at_keys: Vec<(String, serde_json::Value)> = at_map
        .keys()
        .filter(|s| s.to_string().starts_with("k:"))
        .map(|s| {
            let v: serde_json::Value = serde_json::from_str(s.strip_prefix("k:").unwrap()).unwrap();
            (s.to_string(), v)
        })
        .filter(|(_, v)| v.is_object())
        .collect();

    for (position_key, item) in at_keys {
        let mut is_data_set_in_position = true;
        let position_filter = item.as_object().unwrap();
        for (key, value) in position_filter {
            if !data_object.contains_key(key) {
                return None;
            }
            if *data_object.get(key).unwrap() != *value {
                is_data_set_in_position = false;
            }
        }
        if is_data_set_in_position {
            return at_map.get(&position_key);
        }
    }
    None
}

fn check_field_set(
    key: Key,
    is_index_parent: bool,
    field_set: &serde_json::Value,
    data_object: &Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    // info!(
    //     target: "check_field_set",
    //     ?key,
    //     ?is_index_parent,
    //     ?field_set,
    //     ?data_object,
    // );

    let mut at = field_set;
    let at_map = at.as_object().unwrap();
    match key {
        Key::StringKey(s) => {
            if is_index_parent {
                let position = check_position(at_map, data_object);
                match position {
                    Some(v) => at = v,
                    None => return None,
                }
                // info!("key is {} and the at={:?}", s, at);
            }
            let at_map = at.as_object().unwrap();
            let field_key = format!("f:{}", s);
            if !at_map.contains_key(&field_key) && !at_map.contains_key(".") && !at_map.is_empty() {
                let x = serde_json::json!({"!":{}});
                return Some(x);
            }
            at_map.get(&field_key).cloned()
        }
        Key::Index(_i) => Some(at.clone()),
    }
}

fn check_ignore_set(
    key: Key,
    is_index_parent: bool,
    ignore_set: &serde_json::Value,
    data_object: &Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    // info!(
    //     target: "check_field_set",
    //     ?key,
    //     ?is_index_parent,
    //     ?ignore_set,
    //     ?data_object,
    // );

    let mut at = ignore_set;
    let at_map = at.as_object().unwrap();
    match key {
        Key::StringKey(s) => {
            if is_index_parent {
                let position = check_position(at_map, data_object);
                match position {
                    Some(v) => at = v,
                    None => return None,
                }
                // info!("key is {} and the at={:?}", s, at);
            }
            let at_map = at.as_object().unwrap();
            let field_key = format!("f:{}", s);

            if at_map.contains_key(&field_key) || at_map.contains_key(".") {
                let is_specific = match at_map.get(&field_key) {
                    Some(item) => {
                        if let Some(obj) = item.as_object() {
                            obj.is_empty()
                        } else {
                            warn!("Managed fields should be objects. Item is not: {}", item);
                            false
                        }
                    }
                    None => false,
                };

                if is_specific {
                    let x = serde_json::json!({"!":{}});
                    return Some(x);
                }
            }
            at_map.get(&field_key).cloned()
        }
        Key::Index(_i) => Some(at.clone()),
    }
}

fn find_value(resource: &serde_json::Value, jsonpath: &str) -> Result<serde_json::Value> {
    // This jsonpath is not the fully-fledge jsonpath spec. There is a crate for that
    let keys: Vec<&str> = jsonpath.split('.').collect();
    let mut r = resource;

    for key in keys {
        r = r
            .as_object()
            .ok_or_else(|| anyhow!(DocumentError::NotAnObject(format!("{:?}", r))))?
            .get(key)
            .ok_or_else(|| anyhow!(DocumentError::MissingData(key.to_string())))?;
    }

    Ok(r.clone())
}

fn get_string(value: serde_json::Value) -> Result<String> {
    value
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!(DocumentError::NotAString(value.to_string())))
}

fn get_array(value: serde_json::Value) -> Result<Vec<serde_json::Value>> {
    match value {
        serde_json::Value::Array(arr) => Ok(arr),
        other => Err(anyhow!(DocumentError::NotAString(other.to_string()))),
    }
}

/// Read in a yaml or json document for a Kubernetes resource.
/// Must have typemeta fields as well as `name` metadata.
///
/// The `namespace` field in metadata will be set as `default` if missing.
pub fn multi_document_parser_for_k8s_resources(
    path_resource: Option<&String>,
    data_resource: Option<&String>,
) -> Result<HashMap<String, serde_json::Value>> {
    let mut docs = HashMap::new();

    let file = match data_resource {
        Some(s) => s.clone(),
        None => match path_resource {
            Some(p) => std::fs::read_to_string(p).unwrap(),
            None => {
                return Err(anyhow!(DocumentError::MissingDocument));
            }
        },
    };

    for document in serde_yaml::Deserializer::from_str(&file) {
        let d = serde_yaml::Value::deserialize(document)?;
        let value: serde_json::Value = serde_yaml::from_value::<serde_json::Value>(d)?;

        let api_version = get_string(find_value(&value, "apiVersion")?)?;
        let name = get_string(find_value(&value, "metadata.name")?)?;
        let namespace = match find_value(&value, "metadata.namespace") {
            Ok(s) => get_string(s)?,
            Err(_) => String::from("default"),
        };

        if name.is_empty() || namespace.is_empty() || api_version.is_empty() {
            // info!("NO DATA");
        } else {
            let key = format!("{}, {}, {}", api_version, namespace, name);
            docs.insert(key, value);
            // info!(?value);
        }

        //  = serde_yaml::Value::deserialize(document).unwrap();
        // println!("{:?}", value);
    }
    Ok(docs)
}

/// Extracts the `managedFields` from a yaml or json Kubernetes resource manifest.
/// Will aggregate most managed fields used in making diff decisions similar to
/// the k8s-api.
pub fn aggregate_k8s_resources_managed_fields(
    path_resource: Option<&String>,
    data_resource: Option<&String>,
) -> Result<HashMap<String, Option<serde_json::Value>>> {
    let mut docs: HashMap<String, Option<serde_json::Value>> = HashMap::new();

    let file = match data_resource {
        Some(s) => s.clone(),
        None => match path_resource {
            Some(p) => std::fs::read_to_string(p).unwrap(),
            None => {
                return Err(anyhow!(DocumentError::MissingDocument));
            }
        },
    };

    for document in serde_yaml::Deserializer::from_str(&file) {
        let d = serde_yaml::Value::deserialize(document)?;
        let value: serde_json::Value = serde_yaml::from_value::<serde_json::Value>(d)?;

        let api_version = get_string(find_value(&value, "apiVersion")?)?;
        let name = get_string(find_value(&value, "metadata.name")?)?;
        let namespace = match find_value(&value, "metadata.namespace") {
            Ok(s) => get_string(s)?,
            Err(_) => String::from("default"),
        };

        if !name.is_empty() && !namespace.is_empty() && !api_version.is_empty() {
            let key = format!("{}, {}, {}", api_version, namespace, name);
            let managed_fields = get_array(find_value(&value, "metadata.managedFields")?)?;
            let managed_fields_len = managed_fields.len();
            if managed_fields_len == 0 {
                docs.insert(key, None);
                continue;
            }

            let mut fields = serde_json::json!({});
            for managed_field in managed_fields.iter() {
                if [].contains(&managed_field.get("manager").unwrap().as_str().unwrap()) {
                    // Exclude the resources from this manager. If no other manager includes the field,
                    // the specific fields will not be modified.
                    //
                    // Use ignore_sets to ignore fields explicitly instead of omitting management.
                    continue;
                } else {
                    let left = fields.clone();
                    let right = find_value(managed_field, "fieldsV1")?;

                    fields = merge_values(left, right);
                }
            }
            docs.insert(key, Some(fields));
        }
    }
    Ok(docs)
}

pub fn aggregate_managed_fields_to_ignore(
    path_resource: Option<&String>,
    data_resource: Option<&String>,
    ignored_managed_fields: Option<String>,
) -> Result<HashMap<String, Option<serde_json::Value>>> {
    let mut docs: HashMap<String, Option<serde_json::Value>> = HashMap::new();

    let file = match data_resource {
        Some(s) => s.clone(),
        None => match path_resource {
            Some(p) => std::fs::read_to_string(p).unwrap(),
            None => {
                return Err(anyhow!(DocumentError::MissingDocument));
            }
        },
    };

    for document in serde_yaml::Deserializer::from_str(&file) {
        let d = serde_yaml::Value::deserialize(document)?;
        let value: serde_json::Value = serde_yaml::from_value::<serde_json::Value>(d)?;

        let api_version = get_string(find_value(&value, "apiVersion")?)?;
        let name = get_string(find_value(&value, "metadata.name")?)?;
        let namespace = match find_value(&value, "metadata.namespace") {
            Ok(s) => get_string(s)?,
            Err(_) => String::from("default"),
        };

        if !name.is_empty() && !namespace.is_empty() && !api_version.is_empty() {
            let key = format!("{}, {}, {}", api_version, namespace, name);
            let managed_fields = get_array(find_value(&value, "metadata.managedFields")?)?;
            let managed_fields_len = managed_fields.len();
            if managed_fields_len == 0 {
                docs.insert(key, None);
                continue;
            }

            let mut fields = serde_json::json!({});
            if let Some(ref ignored_managed_fields_csv) = ignored_managed_fields {
                let ignored_managed_fields: Vec<&str> =
                    ignored_managed_fields_csv.split(',').collect();
                for managed_field in managed_fields.iter() {
                    for ignored_field in ignored_managed_fields.iter() {
                        if ignored_field.eq(&managed_field
                            .get("manager")
                            .unwrap()
                            .as_str()
                            .unwrap())
                        {
                            fields = merge_values(
                                fields.clone(),
                                find_value(managed_field, "fieldsV1")?,
                            );
                            debug!("matched ignored_fields {}", ignored_field);
                        }
                    }
                }
            }
            docs.insert(key, Some(fields));
        }
    }
    Ok(docs)
}

fn merge_values(left: serde_json::Value, right: serde_json::Value) -> serde_json::Value {
    match (left, right) {
        (serde_json::Value::Object(mut left_map), serde_json::Value::Object(right_map)) => {
            for (key, value) in right_map {
                if let Some(left_value) = left_map.remove(&key) {
                    left_map.insert(key, merge_values(left_value, value));
                } else {
                    left_map.insert(key, value);
                }
            }
            serde_json::Value::Object(left_map)
        }
        (_, right) => right,
    }
}

fn value_option_for_empty_object_or_array(v: &serde_json::Value) -> Option<serde_json::Value> {
    match v {
        serde_json::Value::Array(arr) if arr.is_empty() => Some(json!([])),
        serde_json::Value::Object(obj) if obj.is_empty() => Some(json!({})),
        _ => None,
    }
}

pub fn as_deletion(manifest: String) -> String {
    let s = manifest
        .split("\n")
        .map(String::from)
        .reduce(|acc, line| {
            if line.is_empty() {
                acc
            } else {
                format!("{}\n\x1b[31m- {}\x1b[0m", acc, line)
            }
        })
        .unwrap_or_default()
        .to_string();
    format!("\x1b[31m- {}\x1b[0m", s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ==================== Basic Diff Tests ====================

    #[test]
    fn test_identical_objects_no_diff() {
        let left = json!({"name": "test", "value": 42});
        let right = json!({"name": "test", "value": 42});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(!diff.is_diff(), "Identical objects should have no diff");
    }

    #[test]
    fn test_simple_value_change() {
        let left = json!({"name": "test", "value": 42});
        let right = json!({"name": "test", "value": 100});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Changed value should be detected");
        let changes = diff.ordered_changes();
        assert!(changes.iter().any(|c| c.contains("value")));
    }

    #[test]
    fn test_added_field() {
        let left = json!({"name": "test"});
        let right = json!({"name": "test", "new_field": "added"});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Added field should be detected");
        let changes = diff.ordered_changes();
        assert!(changes
            .iter()
            .any(|c| c.starts_with('+') && c.contains("new_field")));
    }

    #[test]
    fn test_removed_field() {
        let left = json!({"name": "test", "old_field": "to_remove"});
        let right = json!({"name": "test"});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Removed field should be detected");
        let changes = diff.ordered_changes();
        assert!(changes
            .iter()
            .any(|c| c.starts_with('-') && c.contains("old_field")));
    }

    // ==================== Nested Object Tests ====================

    #[test]
    fn test_nested_object_change() {
        let left = json!({
            "metadata": {
                "name": "test",
                "labels": {"app": "old"}
            }
        });
        let right = json!({
            "metadata": {
                "name": "test",
                "labels": {"app": "new"}
            }
        });

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Nested change should be detected");
        let changes = diff.ordered_changes();
        assert!(changes.iter().any(|c| c.contains("app")));
    }

    #[test]
    fn test_deeply_nested_change() {
        let left = json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "app", "image": "v1"}]
                    }
                }
            }
        });
        let right = json!({
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": "app", "image": "v2"}]
                    }
                }
            }
        });

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Deeply nested change should be detected");
    }

    // ==================== Array Tests ====================

    #[test]
    fn test_array_element_change() {
        let left = json!({"items": ["a", "b", "c"]});
        let right = json!({"items": ["a", "x", "c"]});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Array element change should be detected");
    }

    #[test]
    fn test_array_element_added() {
        let left = json!({"items": ["a", "b"]});
        let right = json!({"items": ["a", "b", "c"]});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Added array element should be detected");
        let changes = diff.ordered_changes();
        assert!(changes.iter().any(|c| c.starts_with('+')));
    }

    #[test]
    fn test_array_element_removed() {
        let left = json!({"items": ["a", "b", "c"]});
        let right = json!({"items": ["a", "b"]});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Removed array element should be detected");
        let changes = diff.ordered_changes();
        assert!(changes.iter().any(|c| c.starts_with('-')));
    }

    #[test]
    fn test_array_of_objects_change() {
        let left = json!({
            "containers": [
                {"name": "app", "image": "nginx:1.0"},
                {"name": "sidecar", "image": "envoy:1.0"}
            ]
        });
        let right = json!({
            "containers": [
                {"name": "app", "image": "nginx:2.0"},
                {"name": "sidecar", "image": "envoy:1.0"}
            ]
        });

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Array object change should be detected");
    }

    // ==================== Type Mismatch Tests ====================

    #[test]
    fn test_type_mismatch_string_to_number() {
        let left = json!({"value": "42"});
        let right = json!({"value": 42});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Type mismatch should be detected");
    }

    #[test]
    fn test_type_mismatch_object_to_array() {
        let left = json!({"data": {"key": "value"}});
        let right = json!({"data": ["value"]});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        // This should not panic, even with mismatched types
        let result = diff.do_compare();
        assert!(result.is_ok());
    }

    // ==================== Kubernetes-Specific Tests ====================

    #[test]
    fn test_k8s_deployment_image_change() {
        let left = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-app", "namespace": "default"},
            "spec": {
                "replicas": 3,
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "myapp:v1.0.0",
                            "ports": [{"containerPort": 8080}]
                        }]
                    }
                }
            }
        });
        let right = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-app", "namespace": "default"},
            "spec": {
                "replicas": 3,
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "myapp:v2.0.0",
                            "ports": [{"containerPort": 8080}]
                        }]
                    }
                }
            }
        });

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Image change should be detected");
        let changes = diff.ordered_changes();
        assert!(changes.iter().any(|c| c.contains("image")));
    }

    #[test]
    fn test_k8s_configmap_data_change() {
        let left = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "config"},
            "data": {
                "key1": "value1",
                "key2": "value2"
            }
        });
        let right = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "config"},
            "data": {
                "key1": "value1",
                "key2": "new_value"
            }
        });

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "ConfigMap data change should be detected");
    }

    // ==================== Output Format Tests ====================

    #[test]
    fn test_text_output_contains_changes() {
        let left = json!({"name": "old"});
        let right = json!({"name": "new"});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        let text = diff.text(false);
        assert!(!text.is_empty(), "Text output should not be empty");
    }

    #[test]
    fn test_text_output_manifest_mode() {
        let left = json!({"name": "old"});
        let right = json!({"name": "new"});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        let text_normal = diff.text(false);
        let text_manifest = diff.text(true);

        // Manifest mode should not contain ANSI color codes for removed items
        // (they are filtered out in manifest mode)
        assert_ne!(text_normal, text_manifest);
    }

    #[test]
    fn test_ordered_changes_format() {
        let left = json!({"a": 1, "b": 2});
        let right = json!({"a": 1, "b": 3, "c": 4});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        let changes = diff.ordered_changes();
        // Changes should be prefixed with +, -, or ^
        for change in &changes {
            let first_char = change.chars().next().unwrap();
            assert!(
                first_char == '+' || first_char == '-' || first_char == '^',
                "Change '{}' should start with +, -, or ^",
                change
            );
        }
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_objects() {
        let left = json!({});
        let right = json!({});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(!diff.is_diff(), "Empty objects should have no diff");
    }

    #[test]
    fn test_empty_arrays() {
        let left = json!({"items": []});
        let right = json!({"items": []});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(!diff.is_diff(), "Empty arrays should have no diff");
    }

    #[test]
    fn test_null_values() {
        let left = json!({"value": null});
        let right = json!({"value": null});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(!diff.is_diff(), "Null values should match");
    }

    #[test]
    fn test_null_to_value() {
        let left = json!({"value": null});
        let right = json!({"value": "something"});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Null to value change should be detected");
    }

    #[test]
    fn test_boolean_values() {
        let left = json!({"enabled": true});
        let right = json!({"enabled": false});

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Boolean change should be detected");
    }

    #[test]
    fn test_remove_childrenless_parents() {
        let left = json!({
            "spec": {
                "containers": [{"name": "app"}]
            }
        });
        let right = json!({
            "spec": {}
        });

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        diff.do_compare().unwrap();
        diff.remove_childrenless_parents();

        assert!(diff.is_diff());
    }

    // ==================== Multi-Document Parser Tests ====================

    #[test]
    fn test_multi_document_parser_single_doc() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: test
  namespace: default
data:
  key: value
"#
        .to_string();
        let result = multi_document_parser_for_k8s_resources(None, Some(&yaml));
        assert!(result.is_ok());
        let docs = result.unwrap();
        assert_eq!(docs.len(), 1);
        assert!(docs.contains_key("v1, default, test"));
    }

    #[test]
    fn test_multi_document_parser_multiple_docs() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: config1
  namespace: default
data:
  key: value1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config2
  namespace: default
data:
  key: value2
"#
        .to_string();
        let result = multi_document_parser_for_k8s_resources(None, Some(&yaml));
        assert!(result.is_ok());
        let docs = result.unwrap();
        assert_eq!(docs.len(), 2);
        assert!(docs.contains_key("v1, default, config1"));
        assert!(docs.contains_key("v1, default, config2"));
    }

    #[test]
    fn test_multi_document_parser_cluster_scoped() {
        let yaml = r#"
apiVersion: v1
kind: Namespace
metadata:
  name: my-namespace
"#
        .to_string();
        let result = multi_document_parser_for_k8s_resources(None, Some(&yaml));
        assert!(result.is_ok());
        let docs = result.unwrap();
        // Cluster-scoped resources use 'default' as namespace when not specified
        assert!(docs.contains_key("v1, default, my-namespace"));
    }

    // ==================== as_deletion Tests ====================

    #[test]
    fn test_as_deletion_formatting() {
        let manifest = "apiVersion: v1\nkind: ConfigMap".to_string();
        let result = as_deletion(manifest);

        // Should contain ANSI red color codes
        assert!(result.contains("\x1b[31m"));
        assert!(result.contains("\x1b[0m"));
        // Should contain minus signs
        assert!(result.contains("-"));
    }

    // ==================== Field Set / Ignore Set Tests ====================

    #[test]
    fn test_diff_with_ignore_set() {
        let left = json!({
            "metadata": {
                "name": "test",
                "resourceVersion": "12345",
                "uid": "abc-123"
            },
            "spec": {"replicas": 1}
        });
        let right = json!({
            "metadata": {
                "name": "test",
                "resourceVersion": "67890",
                "uid": "abc-123"
            },
            "spec": {"replicas": 2}
        });

        // Create ignore set for resourceVersion
        let ignore_set = json!({
            "f:metadata": {
                "f:resourceVersion": {}
            }
        });

        let mut diff = Diff::new(Some(left), Some(right), None, Some(ignore_set));
        diff.do_compare().unwrap();

        assert!(diff.is_diff(), "Non-ignored changes should be detected");
        let changes = diff.ordered_changes();
        // resourceVersion should NOT appear in changes
        assert!(!changes.iter().any(|c| c.contains("resourceVersion")));
        // replicas SHOULD appear in changes
        assert!(changes.iter().any(|c| c.contains("replicas")));
    }

    // ==================== Large Document Test ====================

    #[test]
    fn test_large_document_performance() {
        // Create a moderately large document
        let mut containers = Vec::new();
        for i in 0..50 {
            containers.push(json!({
                "name": format!("container-{}", i),
                "image": format!("image:v{}", i),
                "ports": [{"containerPort": 8080 + i}],
                "env": [
                    {"name": "VAR1", "value": "value1"},
                    {"name": "VAR2", "value": "value2"}
                ]
            }));
        }

        let left = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": containers
                    }
                }
            }
        });

        let mut right = left.clone();
        // Change one container image
        right["spec"]["template"]["spec"]["containers"][25]["image"] = json!("image:v25-updated");

        let mut diff = Diff::new(Some(left), Some(right), None, None);
        let result = diff.do_compare();

        assert!(result.is_ok(), "Large document diff should complete");
        assert!(
            diff.is_diff(),
            "Change should be detected in large document"
        );
    }
}
