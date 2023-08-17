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

// We want to make sure that once a parent node is dropped, all its children are dropped as well.
// To do that, we use `Rc<>` for children, and `Weak<>` for parent. (`Rc` because it's single-threaded)
type InnerNodeRef<T> = Rc<InnerNode<T>>;
type InnerNodeWeakRef<T> = Weak<InnerNode<T>>;
type Parent<T> = RefCell<InnerNodeWeakRef<T>>;
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
            parent: RefCell::new(Weak::new()),
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
            let mut childs_parent = new_child.data.parent.borrow_mut();
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
        self.parent.borrow().upgrade().map(|x| Node { data: x })
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
