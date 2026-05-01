# Pre-verification write — C++ / Windows variant

C++ shape identical at the binary level — Win32 APIs unchanged.
See [`../c/README.md`](../c/README.md).

## C++-specific note

RAII wrappers (`std::unique_ptr<HANDLE, ...>` for handles) can
provide automatic cleanup if the destruction logic is set to delete
the file on verification failure. See `wil::unique_hfile` patterns
for an example. The detector must follow vtable / destructor logic
to determine whether RAII covers the cleanup.
