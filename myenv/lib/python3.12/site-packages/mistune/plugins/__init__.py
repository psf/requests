from importlib import import_module

_plugins = {
    'speedup': 'mistune.plugins.speedup.speedup',
    'strikethrough': 'mistune.plugins.formatting.strikethrough',
    'mark': 'mistune.plugins.formatting.mark',
    'insert': 'mistune.plugins.formatting.insert',
    'superscript': 'mistune.plugins.formatting.superscript',
    'subscript': 'mistune.plugins.formatting.subscript',
    'footnotes': 'mistune.plugins.footnotes.footnotes',
    'table': 'mistune.plugins.table.table',
    'url': 'mistune.plugins.url.url',
    'abbr': 'mistune.plugins.abbr.abbr',
    'def_list': 'mistune.plugins.def_list.def_list',
    'math': 'mistune.plugins.math.math',
    'ruby': 'mistune.plugins.ruby.ruby',
    'task_lists': 'mistune.plugins.task_lists.task_lists',
    'spoiler': 'mistune.plugins.spoiler.spoiler',
}
_cached_modules = {}


def import_plugin(name):
    if name in _cached_modules:
        return _cached_modules[name]

    if callable(name):
        return name

    if name in _plugins:
        module_path, func_name = _plugins[name].rsplit(".", 1)
    else:
        module_path, func_name = name.rsplit(".", 1)

    module = import_module(module_path)
    plugin = getattr(module, func_name)
    _cached_modules[name] = plugin
    return plugin
