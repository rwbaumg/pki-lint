#!/bin/bash
# [ 0x19e Networks ]
#  http://0x19e.net
# Author: Robert W. Baumgartner <rwb@0x19e.net>
#
# Allows editing a range of files by locating similar lines.
# Two grep patterns are used to locate lines: the first allows narrowing the context to a block of
# text that contains the actual target line. This is done using a regular expression and an integer
# defining how many lines surrounding each match to include when the next search is performed.
# The final search simply greps for a given target string, which must be an exact match.
# Every match is then processed to construct edit commands.

EDIT_COMMAND="editor"
WRAP_COMMAND="echo bash -c"

GREP_LOCATION="./*"
CONTEXT_REGEX="print\_cyan"
CONTEXT_LINES=20
TARGET_STRING="print_cyan"

IFS=$'\n'; for l in $(grep -rn -P ${CONTEXT_REGEX} ${GREP_LOCATION} -A${CONTEXT_LINES} \
  | grep ${TARGET_STRING} | grep -v -P "(\-|\:)[0-9]+(\-|\:)([\s]+)?\#" \
  | sed -r "s/\-([0-9]+)\-${TARGET_STRING}/\:\1\:${TARGET_STRING}/" \
  | awk -F: '{ printf "+%s %s\n", $2, $1 }'); do bash -c "${EDIT_COMMAND} ${l}"; done

exit $?
