# pki-lint TODO list

- [ ] Update all third-party linting modules to latest versions.
- [ ] Update ```README.md``` to document added arguments.
- [ ] Add argument to specify OpenSSL validation ```auth_level```
- [x] Fix ```NOTES.md``` markdown.
- [x] Fix ```lints/README.md``` markdown formatting.
- [x] Cleanup dependency package handling in ```build.sh``` script.
- [x] Add Ruby and Golang version checks to ```lint.sh``` script.
- [x] Update ```README.md``` to include more detailed information.
- [x] Add support for ```vfychain``` command (eg. ```vfychain -v -pp -u 11 -a ca/subCA.crt -a ca/int.crt -t -a ca/root.crt```; see https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Tools/vfychain)
- [x] Add support for ```certutil``` verification (eg. ```certutil -u Y -d sql:${HOME}/.pki/nssdb```; see https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools/NSS_Tools_certutil)
