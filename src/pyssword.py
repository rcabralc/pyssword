#!/usr/bin/env python
# vim: fdm=marker
"""
pyssword - Password generator

Generates a random password with a specified entropy within specified character
sets.  Uses /dev/urandom for random info by default.

Usage:
    pyssword [--lower --upper --numbers --symbols --entropy=bits --no-info]
    pyssword --read [--lower --upper --numbers --symbols --entropy=bits --no-info --radix=radix --one-based]
    pyssword passphrase [--entropy=bits --no-info]
    pyssword passphrase --read [--entropy=bits --no-info --radix=radix --one-based]
    pyssword passphrase --info
    pyssword --help

Options:

    passphrase
        Output a passphrase instead of a password.  All characters are in
        lowercase.  This uses the EFF's long list, as described in
        https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases

    -e bits --entropy=bits
        [Default: 128]
        The entropy, in bits, of the password.  This is a minimum value; the
        final entropy may be a bit higher than specified due to a round up for
        an integral number of random inputs.

    -l --lower
        Use lowercase letters.

    -u --upper
        Use uppercase letters.

    -n --numbers
        Use numbers.

    -s --symbols
        Use symbols.

    --info
        Ask for a passphrase (a white-space separated list of words of the
        current word list) from stdin.  If connected to a terminal, the user
        will be prompted to enter the passphrase.  Any word not in the word
        list will cause an error.

        Outputs the passphrase info.

    --no-info
        Print only the password, without additional info.

    -r --read
        Ask for random information instead of relying on /dev/urandom.  Numbers
        are collected from stdin until enough entropy has been achieved.  If
        connected to a terminal, the user will be prompted to manually enter
        random numbers.

        Note: In platforms which have no /dev/urandom, this is the only way to
        use the script.

        You can use any source of random data.  But keep in mind that in this
        case the strength of the generated password is entirely dependent on
        the random nature of the numbers provided.  The best way to do so is to
        use real, fair dice or dices, and to actually throw them for getting
        random input values.  Also, numbers are not assumed to be given in
        base-10 by default (see `--radix').

        When connecting stdin to a pipe, there's the possibility of not enough
        numbers be provided, in which case the script will just block
        endlessly, waiting for input.  Be sure to provide enough input in such
        cases.  For the math inclined, the minimum quantity of numbers needed
        for a given radix and entropy (in bits) is:

            total = round_up(entropy_bits / log(radix, 2))

        Or you can just run the program without a pipe and wait for it to ask
        you for numbers.  The prompt has the actual quantity of expected
        numbers.  With this information, cancel it (Control-C) and try again
        using a pipe.

    --radix=radix
        [Default: 256]
        The radix used for random input numbers.  Only used if `--read' is
        given.  Values range from 0 up to but excluding `radix' (see
        `--one-based' for ranging values from 1 up to and including `radix').

    -1 --one-based
        Whether or not numbers are zero- or one- based.  They are assumed to be
        zero-based by default.

    -h --help
        Show this.


Examples:

    Without arguments, all characters are used to compute a password with the
    default entropy (lowercase, uppercase, numbers and symbols):

        $ pyssword --no-info
        &I3`?)R0h0Co0H[>k)|\\

    You can restrict the characters used and use a specific entropy:

        $ pyssword --lower --numbers --entropy 64 --no-info
        azs99hrimiov0g

    By default, that is, without --no-info, additional information is shown:

        $ pyssword --entropy 30
        Actual entropy: 32.772944258388186
        Set length: 94
        Password: h+!:4

    The full character set has 94 letters/numbers/symbols.

    The source of random information can be changed.  For using 16 bytes (that
    is, 128 bits) from /dev/random do the following:

        $ dd if=/dev/random bs=16 count=1 2>/dev/null | od -t u1 -A n -v | pyssword --read --no-info
        )PN"GgyF%`#TdlI3IweV

    Using a real dice with six sides for generating a 26-bit passphrase:

        $ pyssword passphrase --read --radix 6 --one-based --entropy 26
         1/11: 1 2 3 4 5 6 1 2 3 4 5
        Actual entropy: 28.434587507932722
        Set length: 7776
        Password: abacus dispatch arousal

    The same as above, using a pipe and without info:

        $ cat - > /tmp/rolls
        1 2 3 4 5 6 1 2 3 4 5
        <Control-D>
        $ cat /tmp/rolls | pyssword passphrase -e 26 --read --radix 6 --one-based --no-info
        abacus dispatch arousal
        $ shred -u /tmp/rolls

    Note: the two examples above returned three words, but the resulting
    entropy is not 38.8 (each word in Dicerware list provides about 12.9 bits,
    which is what you can get from a list with 7776 words).  This happens
    because in order to get at least 26 bits of entropy eleven dice rolls are
    needed, but then you'll get 28.4 bits.  This value exceeds the entropy
    provided by only two words (25.8 bits), and a third one is needed for
    accounting for the difference and also to satisfy the requirement of at
    least 26 bits.  The entropy which exists is the same that gets in: no
    entropy is created out of thin air, and the script makes its best efforts
    to also not waste it.
"""

from math import ceil, log

import docopt
import itertools
import os
import pkg_resources
import random
import sys


WORDS = []
wordsfile = pkg_resources.resource_stream(
    __name__,
    'eff_large_wordlist.txt'
)
for wordline in wordsfile:
    _base6index, word = wordline.rstrip().split(b'\t')
    WORDS.append(word.decode('us-ascii'))

FULL = [chr(v) for v in range(33, 127)]
UPPER = [chr(v) for v in range(65, 65 + 26)]
LOWER = [chr(v) for v in range(97, 97 + 26)]
NUMBERS = [chr(v) for v in range(48, 48 + 10)]
SYMBOLS = list(set(FULL) - set(NUMBERS) - set(UPPER) - set(LOWER))


class IntOption:
    def __init__(self, args, option):
        self.option = option

        try:
            self.value = int(args[option])
        except ValueError:
            error("{} is not a valid integer".format(option))

    def get(self):
        return self.value

    def greater_than(self, min):
        if self.value <= min:
            error("{} must be greater than {}".format(self.option, min))
        return self

    def less_than(self, max):
        if self.value >= max:
            error("{} must be less than {}".format(self.option, max))
        return self


class Number:
    def __init__(self, radix, digits):
        assert radix > 1
        for digit in digits:
            assert 0 <= digit < radix
        self._radix = radix
        self._digits = digits
        self.max_within_length = radix**len(digits)
        self.bits = log(self.max_within_length, 2)

    def convert(self, radix):
        n = 0
        exp = 0
        minlength = ceil(log(self.max_within_length, radix))

        for digit in reversed(self._digits):
            n += digit * (self._radix**exp)
            exp += 1

        if n == 0:
            digits = [0]
        else:
            digits = []
            while n:
                r = n % radix
                n = n // radix
                digits.append(r)

        padding = [0] * max(minlength - len(digits), 0)

        return self.__class__(radix, padding + list(reversed(digits)))

    def __iter__(self):
        return iter(self._digits)


class TokenSet(tuple):
    @property
    def bits(self):
        return log(len(self), 2)

    def select(self, number):
        return [self[i] for i in number.convert(len(self))]


class CharSet(TokenSet):
    def __new__(cls, tokens):
        if len(tokens) < 2:
            error("Not enough characters to choose from.  Use a longer set.")
        return TokenSet.__new__(cls, tokens)


class WordSet(CharSet):
    def __new__(cls, tokens):
        if len(tokens) < 2:
            error("Not enough words to choose from.  Use a longer set.")
        return CharSet.__new__(cls, tokens)


class Password:
    def __init__(self, tokenset, number):
        self.set = tokenset
        self.entropy = number.bits
        self.value = tokenset.select(number)

    def __iter__(self):
        return iter(self.value)

    def __contains__(self, token):
        return token in self.value


class Passphrase(Password):
    def __init__(self, tokenset, number):
        super(Passphrase, self).__init__(tokenset, number)
        pw = ''.join(self.value)
        loose_entropy = log(len(set(pw))**len(pw), 2) if pw else 0
        self.loose = loose_entropy < self.entropy
        self.entropy = min(self.entropy, loose_entropy)


def error(message):
    print(message)
    sys.exit(1)


def run(args):
    is_passphrase = args['passphrase']

    if is_passphrase:
        tokens = WORDS
    else:
        tokens = []
        tokens.extend(args['--lower'] and LOWER or [])
        tokens.extend(args['--upper'] and UPPER or [])
        tokens.extend(args['--numbers'] and NUMBERS or [])
        tokens.extend(args['--symbols'] and SYMBOLS or [])
        tokens = tokens if len(tokens) else FULL

    assert len(tokens) == len(set(tokens))

    if args['--info']:
        radix = len(tokens)
        generator, entropy = read_words(tokens)
    else:
        entropy = IntOption(args, '--entropy').greater_than(0).get()

        if args['--read']:
            radix = IntOption(args, '--radix').greater_than(1).get()
            generator = user_generator(entropy, radix, args['--one-based'])
        else:
            rng = random.SystemRandom()
            radix = len(tokens)
            generator = random_generator(rng, radix)

    total = ceil(entropy / log(radix, 2))
    inputs = list(itertools.islice(source(generator), total))
    number = Number(radix, inputs)

    if is_passphrase:
        pw = Passphrase(WordSet(tokens), number)
        sep = ' '
    else:
        pw = Password(CharSet(tokens), number)
        sep = ''

    if args['--no-info']:
        if is_passphrase and pw.loose:
            sys.stderr.write('Entropy below requirement.\n')
            sys.stderr.write('Actual entropy: {}\n.'.format(pw.loose_entropy))
        print(sep.join(pw))
    else:
        if is_passphrase and pw.loose:
            print('Entropy below requirement.')
        print("Actual entropy: {}\n"
              "Set length: {}\n"
              "Password: {}"
              "".format(pw.entropy, len(pw.set), sep.join(pw)))


def random_generator(rng, radix):
    while True:
        yield rng.randrange(radix)


def user_generator(desired_entropy, radix, onebased):
    total = ceil(desired_entropy / log(radix, 2))
    promptsize = 2 * len(str(total)) + len('/')
    count = 0
    offset = -1 if onebased else 0

    def readline(line):
        values = line.strip().split(' ')
        try:
            values = [int(value) + offset for value in values if value]
        except:
            values = []

        yield from (v for v in values if 0 <= v < radix)

    while True:
        if sys.stdin.isatty():
            prompt = '{}/{}'.format(count + 1, total)
            print(prompt.rjust(promptsize), end=': ')
            sys.stdout.flush()

        for value in readline(sys.stdin.readline()):
            count += 1
            yield value


def read_words(tokens):
    if sys.stdin.isatty():
        print('Enter words separated by space', end=': ')
        sys.stdout.flush()

    values = []
    for word in sys.stdin.readline().strip().split(' '):
        try:
            values.append(tokens.index(word))
        except ValueError:
            error("{} is not part of the word list.".format(word))

    return (values, log(len(tokens)**len(values), 2))


def source(*inputs):
    return itertools.chain(*[iter(input) for input in inputs])


def main():
    return run(docopt.docopt(__doc__))


if __name__ == '__main__':
    sys.exit(main())
