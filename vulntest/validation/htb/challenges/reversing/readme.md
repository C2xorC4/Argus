Your goal for these validations is to locate a flag within the supplied binary using your reverse engineering tooling.

Flags are found inside each of the challenge applications and are in the format of `HTB{s0me_t3xt}`. When the challenge is still inside an archive, the archive password is typically `hackthebox`.

They were downloaded in order by user difficulty ratings; work through them from oldest on the disk to newest. Extract each to their own directory, work through the challenge, and when the flag is obtained, write it into the local directory and into a manifest within this root directory alongside the name of the challenge.

Use whatever reverse engineering tools you have available. If you need another tool, or new functionality, to complete a challenge flag it for user input.