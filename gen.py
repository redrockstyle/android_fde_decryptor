import argparse
import itertools


def char_range(c1, c2):
    for c in range(ord(c1), ord(c2) + 1):
        yield chr(c)


def main():
    parser = argparse.ArgumentParser(description='Wordlist Generator')
    parser.add_argument('first', help='First char')
    parser.add_argument('second', help='Second char')
    parser.add_argument('size', type=int, help='Size generating')
    parser.add_argument('-o', '--output', help='Write wordlist to file')
    args = parser.parse_args()

    if args.output:
        fw = open(args.output, 'w')
        for elem in itertools.product(''.join([i for i in char_range(args.first, args.second)]), repeat=args.size):
            fw.write(''.join(elem) + '\n')
    else:
        for elem in itertools.product(''.join([i for i in char_range(args.first, args.second)]), repeat=args.size):
            print(''.join(elem))

    return


if __name__ == "__main__":
    main()
