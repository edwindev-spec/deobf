"""Unit tests for deterministic, side-effect-free transformations."""

import unittest

from lua_unveil.cleaner import Cleaner
from lua_unveil.flow import ControlFlowReconstructor
from lua_unveil.lexer import LuaLexer
from lua_unveil.loader import LuaParser
from lua_unveil.strings import (
    StringDecryptor,
    decode_lua_string,
    decode_luraph_style_base85,
    lua_string_to_bytes,
)
from lua_unveil.vm import StackVMDevirtualizer, VMDecoder


class LexerTests(unittest.TestCase):
    def test_long_string_and_comments_are_single_tokens(self):
        source = 'local x = [==[a -- b\n c]==] -- tail\n'
        tokens = LuaLexer().tokenize(source)
        strings = [token for token in tokens if token.kind.value == "string"]
        comments = [token for token in tokens if token.kind.value == "comment"]
        self.assertEqual(len(strings), 1)
        self.assertEqual(len(comments), 1)

    def test_z_escape_can_span_lines(self):
        source = 'local s = "a\\z \n  b"'
        tokens = LuaLexer().tokenize(source)
        self.assertEqual(sum(token.kind.value == "string" for token in tokens), 1)

    def test_structural_validation(self):
        LuaParser().validate('local x = function() if true then return 1 end end')
        with self.assertRaises(Exception):
            LuaParser().validate('if true then return 1')


class StringTests(unittest.TestCase):
    def test_lua_escapes(self):
        self.assertEqual(decode_lua_string(r'"A\x42\067\z  \nD"'), "ABC\nD")
        self.assertEqual(decode_lua_string('[=[\nhello]=]'), "hello")

    def test_char_call_folding(self):
        source = 'local x = string.char(65, 66, 67)'
        result, count = StringDecryptor().decode_char_calls(source)
        self.assertEqual(count, 1)
        self.assertIn('"ABC"', result)

    def test_custom_base85_little_endian(self):
        data = decode_luraph_style_base85('!!!!!')
        self.assertEqual(data, b'\x00\x00\x00\x00')

    def test_string_array_resolution(self):
        source = 'local strings = {"alpha", "beta"}; return strings[2]'
        result, count = StringDecryptor().decode_string_arrays(source)
        self.assertEqual(count, 1)
        self.assertNotIn('local strings', result)
        self.assertIn('return "beta"', result)

    def test_high_byte_escape_is_not_utf8_rewritten(self):
        source = r'local data = "\233"'
        result, count = StringDecryptor().normalize_literals(source)
        self.assertEqual(result, source)
        self.assertEqual(count, 0)

    def test_string_char_emits_byte_escape(self):
        source = 'local data = string.char(233)'
        result, count = StringDecryptor().decode_char_calls(source)
        self.assertEqual(count, 1)
        self.assertIn(r'"\233"', result)


class FlowTests(unittest.TestCase):
    def test_constant_true_branch(self):
        source = 'local x = 0\nif (2 + 3 * 4) == 14 then x = 7 else x = 9 end\nreturn x'
        result, events = ControlFlowReconstructor().reconstruct(source)
        self.assertIn('x = 7', result)
        self.assertNotIn('x = 9', result)
        self.assertEqual(sum(event.count for event in events), 1)

    def test_false_branch_with_elseif(self):
        source = 'if false then A() elseif 3 > 2 then B() else C() end'
        result, _ = ControlFlowReconstructor().reconstruct(source)
        self.assertIn('B()', result)
        self.assertNotIn('A()', result)
        self.assertNotIn('C()', result)

    def test_not_has_lua_precedence(self):
        source = 'if not 1 == 2 then A() else B() end'
        result, _ = ControlFlowReconstructor().reconstruct(source)
        self.assertIn('A()', result)
        self.assertNotIn('B()', result)

    def test_unknown_condition_is_preserved(self):
        source = 'if runtime_flag then A() else B() end'
        result, events = ControlFlowReconstructor().reconstruct(source)
        self.assertEqual(source, result)
        self.assertEqual(events, [])


class CleanerTests(unittest.TestCase):
    def test_unique_short_local_is_renamed(self):
        source = 'local a = 1; print(a)'
        result, events = Cleaner().clean(source, rename=True)
        self.assertIn('local local_001 = 1', result)
        self.assertIn('print(local_001)', result)
        self.assertEqual(events[0].count, 1)

    def test_shadowed_name_is_not_renamed(self):
        source = 'local a = 1; local function f(a) return a end; return a'
        result, _ = Cleaner().clean(source, rename=True)
        self.assertIn('local a = 1', result)


class VMTests(unittest.TestCase):
    def test_symbolic_linear_lift(self):
        bytecode = bytes([0x02, 2, 0, 0, 0, 0x02, 3, 0, 0, 0, 0x10, 0x40])
        program, output, mode = StackVMDevirtualizer().devirtualize(bytecode)
        self.assertEqual(mode, "symbolic")
        self.assertEqual(len(program.instructions), 4)
        self.assertIn('(2 + 3)', output)
        self.assertIn('return value_0001', output)

    def test_branch_program_uses_dispatcher_lift(self):
        bytecode = bytes([
            0x02, 0, 0, 0, 0,       # 0: push 0
            0x31, 8, 0,             # 5: false -> 16
            0x02, 10, 0, 0, 0,      # 8: push 10
            0x30, 5, 0,             # 13: jump -> 21
            0x02, 20, 0, 0, 0,     # 16: push 20
            0x40,                   # 21: return
        ])
        _, output, mode = StackVMDevirtualizer().devirtualize(bytecode)
        self.assertEqual(mode, "dispatcher")
        self.assertIn('goto L_000010', output)
        self.assertIn('::L_000015::', output)

    def test_unknown_opcode_is_rejected(self):
        with self.assertRaises(Exception):
            VMDecoder().decode(b'\xff')


if __name__ == "__main__":
    unittest.main()
