Set-StrictMode -Version Latest

function Initialize-HHForensicsStrictJsonValidator {
    [CmdletBinding()]
    param()

    if ($null -ne ('HostHunter.Forensics.StrictJsonValidator' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;

namespace HostHunter.Forensics
{
    public static class StrictJsonValidator
    {
        private sealed class Scanner
        {
            private readonly string text;
            private readonly int maxDepth;
            private readonly int maxStringBytes;
            private int index;

            internal Scanner(string value, int depth, int stringBytes)
            {
                text = value;
                maxDepth = depth;
                maxStringBytes = stringBytes;
            }

            internal void Validate()
            {
                SkipWhite();
                if (index >= text.Length || text[index] != '{')
                    throw new FormatException("The JSONL root must be an object.");
                ReadObject(1);
                SkipWhite();
                if (index != text.Length)
                    throw new FormatException("Trailing data follows the JSON value.");
            }

            private void ReadValue(int depth)
            {
                SkipWhite();
                if (index >= text.Length) throw new FormatException("A JSON value is missing.");
                char current = text[index];
                if (current == '{') { ReadObject(depth); return; }
                if (current == '[') { ReadArray(depth); return; }
                if (current == '"') { ReadString(); return; }
                if (current == 't') { ReadLiteral("true"); return; }
                if (current == 'f') { ReadLiteral("false"); return; }
                if (current == 'n') { ReadLiteral("null"); return; }
                ReadNumber();
            }

            private void CheckDepth(int depth)
            {
                if (depth > maxDepth) throw new FormatException("The JSON depth limit was exceeded.");
            }

            private void ReadObject(int depth)
            {
                CheckDepth(depth);
                index++;
                SkipWhite();
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                if (Take('}')) return;
                while (true)
                {
                    SkipWhite();
                    if (index >= text.Length || text[index] != '"')
                        throw new FormatException("An object property name is invalid.");
                    string name = ReadString();
                    if (!names.Add(name))
                        throw new FormatException("Duplicate JSON property name: " + name);
                    SkipWhite();
                    Require(':');
                    ReadValue(depth + 1);
                    SkipWhite();
                    if (Take('}')) return;
                    Require(',');
                }
            }

            private void ReadArray(int depth)
            {
                CheckDepth(depth);
                index++;
                SkipWhite();
                if (Take(']')) return;
                while (true)
                {
                    ReadValue(depth + 1);
                    SkipWhite();
                    if (Take(']')) return;
                    Require(',');
                }
            }

            private string ReadString()
            {
                Require('"');
                StringBuilder value = new StringBuilder();
                while (index < text.Length)
                {
                    char current = text[index++];
                    if (current == '"')
                    {
                        string result = value.ToString();
                        if (Encoding.UTF8.GetByteCount(result) > maxStringBytes)
                            throw new FormatException("The JSON string limit was exceeded.");
                        return result;
                    }
                    if (current < 0x20) throw new FormatException("A JSON string contains a control character.");
                    if (current != '\\')
                    {
                        if (Char.IsSurrogate(current)) throw new FormatException("A JSON string contains an unpaired surrogate.");
                        value.Append(current);
                        continue;
                    }
                    if (index >= text.Length) throw new FormatException("A JSON escape is incomplete.");
                    char escape = text[index++];
                    switch (escape)
                    {
                        case '"': value.Append('"'); break;
                        case '\\': value.Append('\\'); break;
                        case '/': value.Append('/'); break;
                        case 'b': value.Append('\b'); break;
                        case 'f': value.Append('\f'); break;
                        case 'n': value.Append('\n'); break;
                        case 'r': value.Append('\r'); break;
                        case 't': value.Append('\t'); break;
                        case 'u':
                            int first = ReadHex();
                            if (first >= 0xD800 && first <= 0xDBFF)
                            {
                                if (index + 1 >= text.Length || text[index] != '\\' || text[index + 1] != 'u')
                                    throw new FormatException("A JSON string contains an unpaired high surrogate.");
                                index += 2;
                                int second = ReadHex();
                                if (second < 0xDC00 || second > 0xDFFF)
                                    throw new FormatException("A JSON string contains an invalid surrogate pair.");
                                value.Append(Char.ConvertFromUtf32(0x10000 + ((first - 0xD800) << 10) + second - 0xDC00));
                            }
                            else
                            {
                                if (first >= 0xDC00 && first <= 0xDFFF)
                                    throw new FormatException("A JSON string contains an unpaired low surrogate.");
                                value.Append((char)first);
                            }
                            break;
                        default: throw new FormatException("A JSON string contains an invalid escape.");
                    }
                }
                throw new FormatException("A JSON string is unterminated.");
            }

            private int ReadHex()
            {
                if (index + 4 > text.Length) throw new FormatException("A Unicode escape is incomplete.");
                int value = 0;
                for (int count = 0; count < 4; count++)
                {
                    int digit = ParseHex(text[index++]);
                    if (digit < 0) throw new FormatException("A Unicode escape contains a non-hex digit.");
                    value = (value << 4) | digit;
                }
                return value;
            }

            private static int ParseHex(char value)
            {
                if (value >= '0' && value <= '9') return value - '0';
                if (value >= 'a' && value <= 'f') return value - 'a' + 10;
                if (value >= 'A' && value <= 'F') return value - 'A' + 10;
                return -1;
            }

            private void ReadLiteral(string value)
            {
                if (index + value.Length > text.Length ||
                    String.CompareOrdinal(text, index, value, 0, value.Length) != 0)
                    throw new FormatException("A JSON literal is invalid.");
                index += value.Length;
            }

            private void ReadNumber()
            {
                int start = index;
                Take('-');
                if (Take('0'))
                {
                    if (index < text.Length && Char.IsDigit(text[index]))
                        throw new FormatException("A JSON number has a leading zero.");
                }
                else
                {
                    int digits = 0;
                    while (index < text.Length && Char.IsDigit(text[index])) { index++; digits++; }
                    if (digits == 0) throw new FormatException("A JSON number is invalid.");
                }
                if (Take('.'))
                {
                    int digits = 0;
                    while (index < text.Length && Char.IsDigit(text[index])) { index++; digits++; }
                    if (digits == 0) throw new FormatException("A JSON fraction is invalid.");
                }
                if (index < text.Length && (text[index] == 'e' || text[index] == 'E'))
                {
                    index++;
                    if (index < text.Length && (text[index] == '+' || text[index] == '-')) index++;
                    int digits = 0;
                    while (index < text.Length && Char.IsDigit(text[index])) { index++; digits++; }
                    if (digits == 0) throw new FormatException("A JSON exponent is invalid.");
                }
                if (index == start) throw new FormatException("A JSON value is invalid.");
            }

            private void SkipWhite()
            {
                while (index < text.Length && (text[index] == ' ' || text[index] == '\t' ||
                    text[index] == '\r' || text[index] == '\n')) index++;
            }

            private bool Take(char expected)
            {
                if (index >= text.Length || text[index] != expected) return false;
                index++;
                return true;
            }

            private void Require(char expected)
            {
                if (!Take(expected)) throw new FormatException("Expected JSON token '" + expected + "'.");
            }
        }

        public static string Validate(byte[] bytes, int maxDepth, int maxStringBytes)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            string text = new UTF8Encoding(false, true).GetString(bytes);
            new Scanner(text, maxDepth, maxStringBytes).Validate();
            return text;
        }
    }
}
'@
}
