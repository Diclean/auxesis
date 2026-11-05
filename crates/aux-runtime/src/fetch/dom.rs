//! The extractor's own small DOM: html5ever builds it through [`TreeSink`]
//! and the readability walkers read it.
//!
//! It replaces `markup5ever_rcdom`, which its authors publish as an
//! unofficial test DOM, not for production. It keeps only what the walkers
//! read: element names and attributes, text, and the tree (children and a
//! weak parent link). Comments, doctypes and processing instructions keep
//! their place in the tree but not their content.
//!
//! Three properties hold for hostile pages:
//! - A `<template>`'s contents are a fragment of their own, never children
//!   of the element, so no walker reads them as page text.
//! - Dropping a tree is iterative ([`Node`]'s `Drop`): a page nested 100k
//!   deep cannot overflow the stack.
//! - No sink method panics. Where html5ever's trait promises an element, a
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
    pub(super) parent: Cell<Option<Weak<Node>>>,
    pub(super) children: RefCell<Vec<Handle>>,
    pub(super) data: NodeData,
}

impl Node {
    fn new(data: NodeData) -> Handle {
        Rc::new(Node {
            parent: Cell::new(None),
            children: RefCell::new(Vec::new()),
            data,
        })
    }

    /// The parent, while it is alive.
    fn parent(&self) -> Option<Handle> {
        let weak = self.parent.take();
        let parent = weak.as_ref().and_then(Weak::upgrade);
        self.parent.set(weak);
        parent
    }

    /// Move out the nodes this one owns: its children and its template
    /// contents.
    fn take_owned(&mut self) -> Vec<Handle> {
        let mut owned = std::mem::take(self.children.get_mut());
        if let NodeData::Element {
            template_contents, ..
        } = &mut self.data
        {
            owned.extend(template_contents.take());
        }
        owned
    }
}

impl Drop for Node {
    /// Free the subtree with an explicit stack, never by recursion. A node
    /// still held elsewhere keeps its own subtree; it is freed the same way
    /// when its last holder drops it.
    fn drop(&mut self) {
        let mut stack = self.take_owned();
        while let Some(node) = stack.pop() {
            if let Ok(mut node) = Rc::try_unwrap(node) {
                // `node` drops at the end of this block with nothing left to
                // own, so its own `drop` does not descend.
                stack.extend(node.take_owned());
            }
        }
    }
}

/// `child`'s live parent and its index there, searched from the end: the
/// tree builder works next to the nodes it added last.
fn parent_and_index(child: &Handle) -> Option<(Handle, usize)> {
    let parent = child.parent()?;
    let index = parent
        .children
        .borrow()
        .iter()
        .rposition(|node| Rc::ptr_eq(node, child))?;
    Some((parent, index))
}

/// Take `node` out of its parent's children.
fn detach(node: &Handle) {
    if let Some((parent, index)) = parent_and_index(node) {
        parent.children.borrow_mut().remove(index);
    }
    node.parent.set(None);
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
                let last = parent.children.borrow().last().cloned();
                if last.is_some_and(|last| merge_text(&last, &text)) {
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
        child.parent.set(Some(Rc::downgrade(parent)));
        parent.children.borrow_mut().push(child);
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
            // "`new_node` may have an old parent": take it out first, so the
            // index below is where it goes.
            detach(node);
        }
        let Some((parent, index)) = parent_and_index(sibling) else {
            return;
        };
        let child = match new_node {
            NodeOrText::AppendNode(node) => node,
            NodeOrText::AppendText(text) => {
                let previous = index
                    .checked_sub(1)
                    .and_then(|before| parent.children.borrow().get(before).cloned());
                if previous.is_some_and(|previous| merge_text(&previous, &text)) {
                    return;
                }
                text_node(text)
            }
        };
        child.parent.set(Some(Rc::downgrade(&parent)));
        parent.children.borrow_mut().insert(index, child);
    }

    fn add_attrs_if_missing(&self, target: &Handle, attrs: Vec<Attribute>) {
        let NodeData::Element { attrs: present, .. } = &target.data else {
            return;
        };
        let mut present = present.borrow_mut();
        let names: HashSet<QualName> = present.iter().map(|attr| attr.name.clone()).collect();
        present.extend(attrs.into_iter().filter(|attr| !names.contains(&attr.name)));
    }

    fn remove_from_parent(&self, target: &Handle) {
        detach(target);
    }

    fn reparent_children(&self, node: &Handle, new_parent: &Handle) {
        let children = std::mem::take(&mut *node.children.borrow_mut());
        for child in &children {
            child.parent.set(Some(Rc::downgrade(new_parent)));
        }
        new_parent.children.borrow_mut().extend(children);
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
