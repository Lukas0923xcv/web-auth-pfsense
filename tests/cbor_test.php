<?php
/* cbor.inc */

function test_cbor_integers(): void {
	foreach ([0, 1, 23, 24, 255, 256, 65535, 65536, 0xffffffff, 0x100000000, PHP_INT_MAX, -1, -24, -25, -256, -257, -65537, PHP_INT_MIN] as $v) {
		t_eq($v, webauthn_cbor_decode(cbor_encode($v)), "integer {$v}");
	}
}

function test_cbor_uint64_beyond_php_int_rejected(): void {
	t_throws(fn() => webauthn_cbor_decode("\x1b\x80\0\0\0\0\0\0\0"), WebAuthnCborException::class, 'out of range');
	t_throws(fn() => webauthn_cbor_decode("\x3b\xff\xff\xff\xff\xff\xff\xff\xff"), WebAuthnCborException::class, 'out of range');
}

function test_cbor_strings_and_bytes_are_distinct(): void {
	t_eq('abc', webauthn_cbor_decode(cbor_encode('abc')));
	$b = webauthn_cbor_decode(cbor_encode(bytes("\x00\xff")));
	t_true($b instanceof WebAuthnCborBytes, 'byte string decodes as WebAuthnCborBytes');
	t_eq("\x00\xff", $b->bytes);
	t_eq('', webauthn_cbor_decode("\x60"));
}

function test_cbor_arrays_maps_simple_values_tags(): void {
	t_eq([1, [2, 3], 'x'], webauthn_cbor_decode(cbor_encode([1, [2, 3], 'x'])));
	t_eq([1 => 2, -1 => 'a', 'fmt' => 'none'], webauthn_cbor_decode(cbor_encode(new TestCborMap([[1, 2], [-1, 'a'], ['fmt', 'none']]))));
	t_eq([false, true, null, null], webauthn_cbor_decode("\x84\xf4\xf5\xf6\xf7"));
	/* Tag 1 (epoch time) around 5: the tag is skipped. */
	t_eq(5, webauthn_cbor_decode("\xc1\x05"));
}

function test_cbor_text_key_cannot_stand_in_for_int_key(): void {
	$m = webauthn_cbor_decode(cbor_encode(new TestCborMap([['3', -7]])));
	t_false(isset($m[3]), 'text key "3" must not become integer key 3');
	t_eq(-7, $m[WEBAUTHN_CBOR_TEXT_KEY_PREFIX . '3']);
	/* Both may appear in one map without colliding. */
	$m = webauthn_cbor_decode(cbor_encode(new TestCborMap([[3, 1], ['3', 2]])));
	t_eq(1, $m[3]);
}

function test_cbor_duplicate_and_bad_map_keys_rejected(): void {
	t_throws(fn() => webauthn_cbor_decode(cbor_encode(new TestCborMap([[1, 1], [1, 2]]))), WebAuthnCborException::class, 'duplicate');
	t_throws(fn() => webauthn_cbor_decode(cbor_encode(new TestCborMap([['a', 1], ['a', 2]]))), WebAuthnCborException::class, 'duplicate');
	t_throws(fn() => webauthn_cbor_decode(cbor_encode(new TestCborMap([[bytes('k'), 1]]))), WebAuthnCborException::class, 'key type');
	t_throws(fn() => webauthn_cbor_decode("\xa1\xf5\x01"), WebAuthnCborException::class, 'key type');
	t_throws(fn() => webauthn_cbor_decode("\xa1\x81\x01\x01"), WebAuthnCborException::class, 'key type');
}

function test_cbor_unsupported_encodings_rejected(): void {
	foreach (["\x5f\x41a\xff" => 'indefinite byte string', "\x9f\xff" => 'indefinite array', "\xbf\xff" => 'indefinite map',
	    "\x1c" => 'reserved info 28', "\x1f" => 'info 31 on major 0', "\xf9\x3c\x00" => 'half float', "\xfa\0\0\0\0" => 'float',
	    "\xfb\0\0\0\0\0\0\0\0" => 'double', "\xe0" => 'simple 0', "\xf8\x20" => 'simple 32', "\xff" => 'break'] as $in => $what) {
		t_throws(fn() => webauthn_cbor_decode($in), WebAuthnCborException::class);
	}
}

function test_cbor_truncated_input_rejected_at_every_length(): void {
	$full = cbor_encode(new TestCborMap([['fmt', 'none'], ['attStmt', new TestCborMap([])],
	    ['authData', bytes(random_bytes(40))], [1, [PHP_INT_MAX, -70000, 'text']]]));
	webauthn_cbor_decode($full);
	for ($i = 0; $i < strlen($full); $i++) {
		t_throws(fn() => webauthn_cbor_decode(substr($full, 0, $i)), WebAuthnCborException::class);
	}
	t_throws(fn() => webauthn_cbor_decode(''), WebAuthnCborException::class, 'truncated');
}

function test_cbor_huge_declared_lengths_rejected(): void {
	t_throws(fn() => webauthn_cbor_decode("\x5b\x7f\xff\xff\xff\xff\xff\xff\xff" . 'ab'), WebAuthnCborException::class, 'truncated');
	t_throws(fn() => webauthn_cbor_decode("\x7a\xff\xff\xff\xff"), WebAuthnCborException::class, 'truncated');
	t_throws(fn() => webauthn_cbor_decode("\x9b\x7f\xff\xff\xff\xff\xff\xff\xff"), WebAuthnCborException::class, 'truncated');
	t_throws(fn() => webauthn_cbor_decode("\xbb\x7f\xff\xff\xff\xff\xff\xff\xff\x01"), WebAuthnCborException::class, 'truncated');
}

function test_cbor_trailing_data_rejected(): void {
	t_throws(fn() => webauthn_cbor_decode("\x01\x02"), WebAuthnCborException::class, 'trailing');
}

function test_cbor_nesting_limit(): void {
	t_eq(1, count(webauthn_cbor_decode(str_repeat("\x81", 16) . "\x01")));
	t_throws(fn() => webauthn_cbor_decode(str_repeat("\x81", 17) . "\x01"), WebAuthnCborException::class, 'deep');
	t_throws(fn() => webauthn_cbor_decode(str_repeat("\xc1", 40) . "\x01"), WebAuthnCborException::class, 'deep');
}

/* Random and mutated input only ever yields a value or WebAuthnCborException. */
function test_cbor_fuzz_never_errors(): void {
	mt_srand(12345);
	$seed = cbor_encode(new TestCborMap([['fmt', 'none'], ['authData', bytes(str_repeat('A', 20))], [-2, [1, 'x', null]]]));
	for ($n = 0; $n < 3000; $n++) {
		if ($n % 2) {
			$in = '';
			for ($i = mt_rand(0, 24); $i > 0; $i--) {
				$in .= chr(mt_rand(0, 255));
			}
		} else {
			$in = $seed;
			for ($i = mt_rand(1, 3); $i > 0; $i--) {
				$in[mt_rand(0, strlen($in) - 1)] = chr(mt_rand(0, 255));
			}
		}
		try {
			webauthn_cbor_decode($in);
		} catch (WebAuthnCborException $e) {
		}
	}
	t_true(true);
}
