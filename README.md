Slog
====

A simple log library written in C++ 11.

Build
-----

    cmake . && make

Platforms
---------

* Mac OSX(clang)
* Linux(gcc)

Features
--------

* Header Only
* User define struct formatting
* Rotating log files

Formatting
----------

`{}` is a placeholder for a argument, the number in the placeholder is the index of argument, e.g. `{0}` is a placeholder for the first argument.

###Alignment

The fill character is provided normally in conjunction with the `width` parameter. This indicates that if the value being formatted is smaller than `width` some extra characters will be printed around it. e.g. `{0:<#10}` the `:` is separated character, the `#` is fill character, the `10` is `width`, and `<` is the alignment option. The alignment can be one of the following options:

* `<` - the argument is left-aligned in `width` columns
* `>` - the argument is right-aligned in `width` columns
* `^` - the argument is center-aligned in `width` columns

Space is default fill character, right align is default alignment.
