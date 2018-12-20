This is a library for querying the [pwnedkeys.com](https://pwnedkeys.com) API.
It allows you to provide a public key, and determine whether or not the
corresponding public key has ever been exposed to the public, rendering it
permanently unsafe to use.

Due to recent changes in the `openssl` standard library, this code requires
at least Ruby 2.5 to run.


# Installation

It's a gem!

    gem install pwnedkeys-api-client

If you're the sturdy type that likes to run from git:

    rake install

Or, if you've eschewed the convenience of Rubygems entirely, then you
presumably know what to do already.


# Usage

To query for a pwned key, simply create a new `Pwnedkeys::Request`, passing in
the public key you want to query for:

    require "pwnedkeys/request"

    key = OpenSSL::PKey.read("/tmp/suss_key")
	query = Pwnedkeys::Request.new(key)

Then, just ask whether it's pwned!

    query.pwned?

You'll get back a `true` or `false` answer in next-to-no-time.  If any problems
crop up (like the signature can't be validated, or the API doesn't respond) you'll
get a `Pwnedkeys::Request::Error` exception.


# Contributing

See `CONTRIBUTING.md`.


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2018  Matt Palmer <matt@hezmatt.org>

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

	In addition, as a special exception, the copyright holders give permission
	to link the code of portions of this program with the OpenSSL library. You
	must obey the GNU General Public License in all respects for all of the
	code used other than OpenSSL. If you modify file(s) with this exception,
	you may extend this exception to your version of the file(s), but you are
	not obligated to do so. If you do not wish to do so, delete this exception
	statement from your version. If you delete this exception statement from
	all source files in the program, then also delete it here.
