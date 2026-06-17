adaptivexc2のペイロードデカすぎるのでほぼ使えない。
```python
#!/usr/bin/env python3
"""
shell_to_vba.py
rawシェルコード(.bin) を VBA の Array() 形式に変換する
"""

import argparse
import sys
import os


def main():
    parser = argparse.ArgumentParser(
        description="rawシェルコード(.bin) → VBA Array() 変換ツール"
    )
    parser.add_argument("input", help="入力シェルコードファイル (.bin)")
    parser.add_argument("-x", "--xor", type=lambda v: int(v, 0), metavar="KEY",
                        help="XORキー (例: 0x41 または 65)")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[ERROR] ファイルが見つかりません: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "rb") as f:
        data = f.read()

    if args.xor is not None:
        data = bytes(b ^ args.xor for b in data)

    values = ", ".join(str(b) for b in data)
    print(f"buf = Array({values})")


if __name__ == "__main__":
    main()
```