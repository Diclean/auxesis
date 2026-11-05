//! The extractor's own small DOM: html5ever builds it through [`TreeSink`]
//! and the readability walkers read it.
//!
//! It replaces `markup5ever_rcdom`, which its authors publish as an
//! unofficial test DOM, not for production. It keeps only what the walkers
//! read: element names and attributes, text, and the tree. Comments,
//! doctypes and processing instructions keep their place in the tree but not
//! their content.
//!
//! A node's children are a linked list: a node holds its first child and its
//! next sibling (strong links), and its parent, its previous sibling and its
//! last child (weak links). Appending, inserting before a sibling and
//! detaching therefore take a few steps however many siblings a node has.
//! Two sink steps cost more, in proportion to what they touch:
//! [`TreeSink::reparent_children`] walks the children it moves and
//! [`TreeSink::add_attrs_if_missing`] the attributes it compares. The
//! budgeted sink in `readability.rs` charges that work before it runs.
//!
//! Three properties hold for hostile pages:
//! - A `<template>`'s contents are a fragment of their own, never children
//!   of the element, so no walker reads them as page text.
//! - Dropping a tree is iterative ([`Node`]'s `Drop`): a page nested 100k
//!   deep, or 100k siblings wide, cannot overflow the stack.
//! - No sink method panics. The links sit in `Cell`s that are only taken and
//!   put back, never borrowed. Where html5ever's trait promises an element, a
//!   template or a parent that is not there, the sink answers a blank name or
//!   a detached fragment, or leaves the node out of the tree.

use html5ever::tendril::StrTendril;
use html5ever::tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink};
use html5ever::{Attribute, ExpandedName, LocalName, Namespace, QualName};
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::{Rc, Weak};

/// A shared reference to a [`Node`].
pub(super) type Handle = Rc<Node>;

/// What a node is.
pub(super) enum NodeData {
    Document,
    Doctype,
    Text {
        contents: RefCell<StrTendril>,
    },
    Comment,
    ProcessingInstruction,
    Element {
        name: QualName,
        attrs: RefCell<Vec<Attribute>>,
        /// A `<template>`'s contents: outside the element's children.
        template_contents: Option<Handle>,
        mathml_annotation_xml_integration_point: bool,
    },
}

/// One node of the tree.
pub(super) struct Node {
    /// `None` for the document, a template's contents or a detached node.
    parent: Cell<Option<Weak<Node>>>,
    previous_sibling: Cell<Option<Weak<Node>>>,
    next_sibling: Cell<Option<Handle>>,
    first_child: Cell<Option<Handle>>,
    last_child: Cell<Option<Weak<Node>>>,
    pub(super) data: NodeData,
}

/// A copy of a strong link; the link stays in place.
fn strong(link: &Cell<Option<Handle>>) -> Option<Handle> {
    let node = link.take();
    link.set(node.clone());
    node
}

/// The node behind a weak link, while it is alive; the link stays in place.
fn weak(link: &Cell<Option<Weak<Node>>>) -> Option<Handle> {
    let target = link.take();
    let node = target.as_ref().and_then(Weak::upgrade);
    link.set(target);
    node
}

impl Node {
    fn new(data: NodeData) -> Handle {
        Rc::new(Node {
            parent: Cell::new(None),
            previous_sibling: Cell::new(None),
            next_sibling: Cell::new(None),
            first_child: Cell::new(None),
            last_child: Cell::new(None),
            data,
        })
    }

    /// The parent, while it is alive.
    pub(super) fn parent(&self) -> Option<Handle> {
        weak(&self.parent)
    }

    /// The children, first to last.
    pub(super) fn children(&self) -> Children {
        Children {
            next: strong(&self.first_child),
        }
    }

    /// Unlink every child and hand them back, first to last, each with no
    /// parent and no siblings left.
    pub(super) fn take_children(&self) -> Vec<Handle> {
        self.last_child.set(None);
        let mut children = Vec::new();
        let mut next = self.first_child.take();
        while let Some(child) = next {
            next = child.next_sibling.take();
            child.previous_sibling.set(None);
            child.parent.set(None);
            children.push(child);
        }
        children
    }

    /// Move out the nodes this one owns: its first child, its next sibling
    /// and its template contents.
    fn take_owned(&mut self) -> [Option<Handle>; 3] {
        let template = match &mut self.data {
            NodeData::Element {
                template_contents, ..
            } => template_contents.take(),
            _ => None,
        };
        [
            self.first_child.get_mut().take(),
            self.next_sibling.get_mut().take(),
            template,
        ]
    }
}

impl Drop for Node {
    /// Free the subtree and the later siblings with an explicit stack, never
    /// by recursion. A node still held elsewhere keeps what it owns; that is
    /// freed the same way when its last holder drops it.
    fn drop(&mut self) {
        let mut stack: Vec<Handle> = self.take_owned().into_iter().flatten().collect();
        while let Some(node) = stack.pop() {
            if let Ok(mut node) = Rc::try_unwrap(node) {
                // `node` drops at the end of this block with nothing left to
                // own, so its own `drop` does not descend.
                stack.extend(node.take_owned().into_iter().flatten());
            }
        }
    }
}

/// The children of a node, first to last ([`Node::children`]).
pub(super) struct Children {
    next: Option<Handle>,
}

impl Iterator for Children {
    type Item = Handle;

    fn next(&mut self) -> Option<Handle> {
        let node = self.next.take()?;
        self.next = strong(&node.next_sibling);
        Some(node)
    }
}

/// Take `node` out of its parent's children: its neighbours link to each
/// other, and it keeps no parent and no siblings.
fn detach(node: &Handle) {
    let parent = node.parent.take().and_then(|parent| parent.upgrade());
    let previous = node
        .previous_sibling
        .take()
        .and_then(|previous| previous.upgrade());
    let next = node.next_sibling.take();
    if let Some(next) = &next {
        next.previous_sibling
            .set(previous.as_ref().map(Rc::downgrade));
    } else if let Some(parent) = &parent {
        parent.last_child.set(previous.as_ref().map(Rc::downgrade));
    }
    if let Some(previous) = &previous {
        previous.next_sibling.set(next);
    } else if let Some(parent) = &parent {
        parent.first_child.set(next);
    }
}

/// Link `child`, which has no parent and no siblings, as `parent`'s last
/// child.
fn push_child(parent: &Handle, child: Handle) {
    let last = weak(&parent.last_child);
    child.parent.set(Some(Rc::downgrade(parent)));
    child.previous_sibling.set(last.as_ref().map(Rc::downgrade));
    parent.last_child.set(Some(Rc::downgrade(&child)));
    match last {
        Some(last) => last.next_sibling.set(Some(child)),
        None => parent.first_child.set(Some(child)),
    }
}

/// Link `child`, which has no parent and no siblings, right before
/// `sibling`, a child of `parent`.
fn insert_before(parent: &Handle, sibling: &Handle, child: Handle) {
    let previous = weak(&sibling.previous_sibling);
    child.parent.set(Some(Rc::downgrade(parent)));
    child
        .previous_sibling
        .set(previous.as_ref().map(Rc::downgrade));
    child.next_sibling.set(Some(sibling.clone()));
    sibling.previous_sibling.set(Some(Rc::downgrade(&child)));
    match previous {
        Some(previous) => previous.next_sibling.set(Some(child)),
        None => parent.first_child.set(Some(child)),
    }
}

/// Add `text` to `node` when it is a text node.
fn merge_text(node: &Handle, text: &str) -> bool {
    match &node.data {
        NodeData::Text { contents } => {
            contents.borrow_mut().push_slice(text);
            true
        }
        _ => false,
    }
}

fn text_node(text: StrTendril) -> Handle {
    Node::new(NodeData::Text {
        contents: RefCell::new(text),
    })
}

/// The tree html5ever builds through the [`TreeSink`] below.
pub(super) struct Dom {
    pub(super) document: Handle,
    /// What `elem_name` answers for a node that is not an element.
    no_name: QualName,
}

impl Default for Dom {
    fn default() -> Self {
        Dom {
            document: Node::new(NodeData::Document),
            no_name: QualName::new(None, Namespace::default(), LocalName::default()),
        }
    }
}

impl TreeSink for Dom {
    type Handle = Handle;
    type Output = Dom;
    type ElemName<'a>
        = ExpandedName<'a>
    where
        Self: 'a;

    fn finish(self) -> Dom {
        self
    }

    // Parse errors and the quirks mode change nothing the walkers read.
    fn parse_error(&self, _msg: Cow<'static, str>) {}

    fn set_quirks_mode(&self, _mode: QuirksMode) {}

    fn get_document(&self) -> Handle {
        self.document.clone()
    }

    fn elem_name<'a>(&'a self, target: &'a Handle) -> ExpandedName<'a> {
        match &target.data {
            NodeData::Element { name, .. } => name.expanded(),
            _ => self.no_name.expanded(),
        }
    }

    fn create_element(&self, name: QualName, attrs: Vec<Attribute>, flags: ElementFlags) -> Handle {
        Node::new(NodeData::Element {
            name,
            attrs: RefCell::new(attrs),
            template_contents: flags.template.then(|| Node::new(NodeData::Document)),
            mathml_annotation_xml_integration_point: flags.mathml_annotation_xml_integration_point,
        })
    }

    fn create_comment(&self, _text: StrTendril) -> Handle {
        Node::new(NodeData::Comment)
    }

    fn create_pi(&self, _target: StrTendril, _data: StrTendril) -> Handle {
        Node::new(NodeData::ProcessingInstruction)
    }

    fn append(&self, parent: &Handle, child: NodeOrText<Handle>) {
        let child = match child {
            NodeOrText::AppendText(text) => {
                if weak(&parent.last_child).is_some_and(|last| merge_text(&last, &text)) {
                    return;
                }
                text_node(text)
            }
            NodeOrText::AppendNode(node) => {
                // html5ever appends only parentless nodes; detaching anyway
                // keeps every node in one place.
                detach(&node);
                node
            }
        };
        push_child(parent, child);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Handle,
        prev_element: &Handle,
        child: NodeOrText<Handle>,
    ) {
        if element.parent().is_some() {
            self.append_before_sibling(element, child);
        } else {
            self.append(prev_element, child);
        }
    }

    fn append_doctype_to_document(
        &self,
        _name: StrTendril,
        _public_id: StrTendril,
        _system_id: StrTendril,
    ) {
        let doctype = Node::new(NodeData::Doctype);
        self.append(&self.document, NodeOrText::AppendNode(doctype));
    }

    fn get_template_contents(&self, target: &Handle) -> Handle {
        match &target.data {
            NodeData::Element {
                template_contents: Some(contents),
                ..
            } => contents.clone(),
            // Not a template: a detached fragment, whose content never
            // reaches the page.
            _ => Node::new(NodeData::Document),
        }
    }

    fn same_node(&self, x: &Handle, y: &Handle) -> bool {
        Rc::ptr_eq(x, y)
    }

    fn append_before_sibling(&self, sibling: &Handle, new_node: NodeOrText<Handle>) {
        if let NodeOrText::AppendNode(node) = &new_node {
            // "`new_node` may have an old parent": take it out first, so it
            // is not linked twice.
            detach(node);
        }
        let Some(parent) = sibling.parent() else {
            return;
        };
        let child = match new_node {
            NodeOrText::AppendNode(node) => node,
            NodeOrText::AppendText(text) => {
                let previous = weak(&sibling.previous_sibling);
                if previous.is_some_and(|previous| merge_text(&previous, &text)) {
                    return;
                }
                text_node(text)
            }
        };
        insert_before(&parent, sibling, child);
    }

    fn add_attrs_if_missing(&self, target: &Handle, attrs: Vec<Attribute>) {
        let NodeData::Element { attrs: present, .. } = &target.data else {
            return;
        };
        let mut present = present.borrow_mut();
        let missing: Vec<Attribute> = {
            let names: HashSet<&QualName> = present.iter().map(|attr| &attr.name).collect();
            attrs
                .into_iter()
                .filter(|attr| !names.contains(&attr.name))
                .collect()
        };
        present.extend(missing);
    }

    fn remove_from_parent(&self, target: &Handle) {
        detach(target);
    }

    fn reparent_children(&self, node: &Handle, new_parent: &Handle) {
        for child in node.take_children() {
            push_child(new_parent, child);
        }
    }

    fn is_mathml_annotation_xml_integration_point(&self, target: &Handle) -> bool {
        matches!(
            target.data,
            NodeData::Element {
                mathml_annotation_xml_integration_point: true,
                ..
            }
        )
    }

    // `maybe_clone_an_option_into_selectedcontent` keeps html5ever's no-op
    // default: a `<selectedcontent>` sits inside a `<select>`, which the
    // walkers drop with all it holds.
}
