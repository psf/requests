import re

__all__ = ['task_lists']


TASK_LIST_ITEM = re.compile(r'^(\[[ xX]\])\s+')


def task_lists_hook(md, state):
    return _rewrite_all_list_items(state.tokens)


def render_task_list_item(renderer, text, checked=False):
    checkbox = (
        '<input class="task-list-item-checkbox" '
        'type="checkbox" disabled'
    )
    if checked:
        checkbox += ' checked/>'
    else:
        checkbox += '/>'

    if text.startswith('<p>'):
        text = text.replace('<p>', '<p>' + checkbox, 1)
    else:
        text = checkbox + text

    return '<li class="task-list-item">' + text + '</li>\n'


def task_lists(md):
    """A mistune plugin to support task lists. Spec defined by
    GitHub flavored Markdown and commonly used by many parsers:

    .. code-block:: text

        - [ ] unchecked task
        - [x] checked task

    :param md: Markdown instance
    """
    md.before_render_hooks.append(task_lists_hook)
    if md.renderer and md.renderer.NAME == 'html':
        md.renderer.register('task_list_item', render_task_list_item)


def _rewrite_all_list_items(tokens):
    for tok in tokens:
        if tok['type'] == 'list_item':
            _rewrite_list_item(tok)
        if 'children' in tok:
            _rewrite_all_list_items(tok['children'])
    return tokens


def _rewrite_list_item(tok):
    children = tok['children']
    if children:
        first_child = children[0]
        text = first_child.get('text', '')
        m = TASK_LIST_ITEM.match(text)
        if m:
            mark = m.group(1)
            first_child['text'] = text[m.end():]

            tok['type'] = 'task_list_item'
            tok['attrs'] = {'checked': mark != '[ ]'}
