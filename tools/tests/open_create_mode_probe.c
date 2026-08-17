/* SPDX-License-Identifier: MPL-2.0 */
/* Verify Linux open(2) access semantics for a newly created inode. */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    static const char writable_path[] = "/tmp/edgeos-open-create-mode-rw";
    static const char readonly_path[] = "/tmp/edgeos-open-create-mode-ro";
    char value = 0;
    int descriptor;

    unlink(writable_path);
    descriptor = open(writable_path, O_RDWR | O_CREAT | O_EXCL, 0444);
    if (descriptor < 0) {
        perror("open O_RDWR|O_CREAT mode 0444");
        return 1;
    }
    if (write(descriptor, "x", 1) != 1 || lseek(descriptor, 0, SEEK_SET) != 0 ||
        read(descriptor, &value, 1) != 1 || value != 'x') {
        perror("newly created read/write descriptor");
        return 1;
    }
    close(descriptor);

    errno = 0;
    descriptor = open(writable_path, O_WRONLY);
    if (descriptor >= 0 || errno != EACCES) {
        fprintf(stderr, "reopen mode 0444 result=%d errno=%d (%s)\n",
                descriptor, errno, strerror(errno));
        return 1;
    }

    unlink(readonly_path);
    descriptor = open(readonly_path, O_RDONLY | O_CREAT | O_EXCL, 0000);
    if (descriptor < 0) {
        perror("open O_RDONLY|O_CREAT mode 0000");
        return 1;
    }
    if (read(descriptor, &value, 1) != 0) {
        perror("read newly created mode 0000 file");
        return 1;
    }
    close(descriptor);
    unlink(writable_path);
    unlink(readonly_path);
    puts("open_create_mode: PASS");
    return 0;
}
