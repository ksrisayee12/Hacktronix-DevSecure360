import tree_sitter_language_pack as lp
from tree_sitter import Parser

# Verify node API compatibility
p = lp.get_parser('python')
code = b'x = request.args.get("name")'
result = p.parse(code)
root = result.root_node
for child in root.children:
    print('node type:', child.type, '| text:', code[child.start_byte:child.end_byte])

print('start_point:', root.children[0].start_point)

# Also test Parser(lang) constructor style
p2 = Parser(lp.get_language('javascript'))
t2 = p2.parse(b'var x = 1;')
print('Parser(lang) constructor works:', t2.root_node.type)

# Test child_by_field_name still works
code2 = b'x = 1 + 2'
t3 = p.parse(code2)
assign = t3.root_node.children[0]
print('assignment node:', assign.type)
left = assign.child_by_field_name('left')
right = assign.child_by_field_name('right')
print('left:', code2[left.start_byte:left.end_byte] if left else None)
print('right:', code2[right.start_byte:right.end_byte] if right else None)
