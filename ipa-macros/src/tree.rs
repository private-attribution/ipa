use std::{
    cell::RefCell,
    fmt::Debug,
    ops::Deref,
    rc::{Rc, Weak},
};

#[derive(Clone, Debug)]
pub struct Node<T> {
    data: InnerNodeRef<T>,
}

#[derive(Clone, Debug)]
struct InnerParent<T> {
    weak: RefCell<InnerNodeWeakRef<T>>,
    strong: RefCell<Option<InnerNodeRef<T>>>,
}

// We want to make sure that once a parent node is dropped, all its children are dropped as well.
// To do that, we use `Rc<>` for children, and `Weak<>` for parent. (`Rc` because it's single-threaded)
type InnerNodeRef<T> = Rc<InnerNode<T>>;
type InnerNodeWeakRef<T> = Weak<InnerNode<T>>;
type Parent<T> = InnerParent<T>;
type Children<T> = RefCell<Vec<InnerNodeRef<T>>>;

#[derive(Clone, Debug)]
pub struct InnerNode<T> {
    value: T,
    parent: Parent<T>,
    children: Children<T>,
}

impl<T> Node<T> {
    pub fn new(value: T) -> Self {
        let new_node = InnerNode {
            value,
            parent: InnerParent {
                weak: RefCell::new(Weak::new()),
                strong: RefCell::new(None),
            },
            children: RefCell::new(Vec::new()),
        };
        Node {
            data: Rc::new(new_node),
        }
    }

    fn get_copy(&self) -> InnerNodeRef<T> {
        Rc::clone(&self.data)
    }

    pub fn add_child(&self, value: T) -> Node<T> {
        let new_child = Node::new(value);
        {
            let mut my_children = self.data.children.borrow_mut();
            my_children.push(new_child.get_copy());
        } // drop the borrow
        {
            let mut childs_parent = new_child.data.parent.weak.borrow_mut();
            *childs_parent = Rc::downgrade(&self.get_copy());
        } // drop the borrow
        new_child
    }

    pub fn get_children(&self) -> Vec<Node<T>> {
        self.children
            .borrow()
            .iter()
            .map(|x| Node { data: Rc::clone(x) })
            .collect::<Vec<_>>()
    }

    pub fn get_parent(&self) -> Option<Node<T>> {
        if self.parent.strong.borrow().is_some() {
            return Some(Node {
                data: Rc::clone(self.parent.strong.borrow().as_ref().unwrap()),
            });
        }

        self.parent
            .weak
            .borrow()
            .upgrade()
            .map(|x| Node { data: x })
    }

    /// Returns a new node with the same data, but with a strong reference to
    /// its parent. This is useful when you want to keep a node alive, and also
    /// want to access its immediate parent.
    pub fn upgrade(&self) -> Node<T> {
        if let Some(parent) = self.parent.weak.borrow().upgrade() {
            let mut strong_parent = self.parent.strong.borrow_mut();
            *strong_parent = Some(parent);
        };
        Node {
            data: Rc::clone(&self.get_copy()),
        }
    }

    /// Returns a new node with the same data, but drops the strong reference
    /// to its parent. It only makes sense to call this method if you have
    /// previously called `upgrade()`.
    #[allow(dead_code)]
    pub fn downgrade(&self) -> Node<T> {
        self.parent.strong.take();
        Node {
            data: Rc::clone(&self.get_copy()),
        }
    }
}

impl<T> Deref for Node<T> {
    type Target = InnerNode<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> Deref for InnerNode<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use std::rc::{Rc, Weak};

    use crate::tree::Node;

    #[derive(Debug)]
    struct TestData(u8);

    #[test]
    fn children() {
        let root = Node::new(TestData(0));
        root.add_child(TestData(1));
        root.add_child(TestData(2));
        let children = root.get_children();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].value.0, 1);
        assert_eq!(children[1].value.0, 2);
    }

    #[test]
    fn parent() {
        let root = Node::new(TestData(0));
        root.add_child(TestData(1));
        let child = root.add_child(TestData(2));
        let parent = child.get_parent().unwrap();
        assert_eq!(parent.value.0, 0);
    }

    #[test]
    fn parent_nodes_are_dropped() {
        #[allow(unused_assignments)]
        let mut grandchild: Option<Node<TestData>> = None;
        {
            let root = Node::new(TestData(0));
            let child = root.add_child(TestData(1));
            grandchild = Some(child.add_child(TestData(2)));
            assert_eq!(child.value.0, 1);
            assert_eq!(child.get_parent().unwrap().value.0, 0);
            assert_eq!(grandchild.as_ref().unwrap().value.0, 2);
            assert_eq!(
                grandchild.as_ref().unwrap().get_parent().unwrap().value.0,
                1
            );
        }
        assert_eq!(grandchild.as_ref().unwrap().value.0, 2);
        assert!(grandchild.as_ref().unwrap().get_parent().is_none());
    }

    #[test]
    fn parent_node_is_not_dropped_if_pinned() {
        #[allow(unused_assignments)]
        let mut grandchild: Option<Node<TestData>> = None;
        {
            let root = Node::new(TestData(0));
            let child = root.add_child(TestData(1));
            grandchild = Some(child.add_child(TestData(2)));
            assert_eq!(child.value.0, 1);
            assert_eq!(child.get_parent().unwrap().value.0, 0);
            assert_eq!(grandchild.as_ref().unwrap().value.0, 2);
            assert_eq!(
                grandchild.as_ref().unwrap().get_parent().unwrap().value.0,
                1
            );
            grandchild = Some(grandchild.as_ref().unwrap().upgrade());
        }

        // Since we called `upgrade()` on the grandchild, it holds a strong reference to its parent node.
        assert_eq!(grandchild.as_ref().unwrap().value.0, 2);
        {
            let parent = grandchild.as_ref().unwrap().get_parent().unwrap();
            assert_eq!(parent.value.0, 1);
            assert!(parent.get_parent().is_none());
        } // drop parent

        // The local reference to the parent is dropped. The only reference to the parent is now
        // held by the grandchild. Calling `downgrade()` will drop the reference to the parent.
        grandchild = Some(grandchild.as_ref().unwrap().downgrade());
        assert_eq!(grandchild.as_ref().unwrap().value.0, 2);
        assert!(grandchild.as_ref().unwrap().get_parent().is_none());
    }

    #[test]
    fn all_nodes_are_dropped() {
        #[allow(unused_assignments)]
        let mut grandchild_weak: Weak<Node<TestData>> = Weak::new();
        {
            let root = Node::new(TestData(0));
            let child = root.add_child(TestData(1));
            let grandchild_ref = Rc::new(child.add_child(TestData(2)));
            grandchild_weak = Rc::downgrade(&Rc::clone(&grandchild_ref));
            assert_eq!(child.value.0, 1);
            assert_eq!(child.get_parent().unwrap().value.0, 0);
            assert_eq!(grandchild_weak.upgrade().unwrap().value.0, 2);
            assert_eq!(
                grandchild_weak
                    .upgrade()
                    .unwrap()
                    .get_parent()
                    .unwrap()
                    .value
                    .0,
                1
            );
        }
        assert!(grandchild_weak.upgrade().is_none());
    }
}
