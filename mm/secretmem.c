// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/memfd.h>
#include <linux/pseudo_fs.h>
#include <linux/set_memory.h>
#include <uapi/linux/memfd.h>
#include <uapi/linux/magic.h>

#include <asm/tlb.h>

#define SECRETMEM_EXCLUSIVE    0x1
#define SECRETMEM_UNCACHED     0x2

struct secretmem_state {
	unsigned int mode;
};

static vm_fault_t secretmem_fault(struct vm_fault *vmf)
{
	struct secretmem_state *state = vmf->vma->vm_file->private_data;
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	pgoff_t offset = vmf->pgoff;
	unsigned long addr;
	struct page *page;
	pgoff_t index;
	int err = 0;

	//printk("%s():: on vma\n", __func__);
	//dump_vma(vmf->vma);

	printk("%s():: state of page cache for this address_space mapping\n", __func__);
	xa_for_each(&mapping->i_pages, index, page) {
		get_page(page);
		lock_page(page);
		addr = (unsigned long)page_address(page);
		printk("%s()::page addr is %16lx page_count(page) is %d content is %s \n",
				   __func__, addr, page_count(page), (char *)addr);
		unlock_page(page);
		put_page(page);
	}

	page = find_get_page(mapping, offset);
	if (page){
		printk("%s()::page found\n", __func__);
		addr = (unsigned long)page_address(page);
		printk("%s()::page addr is %16lx page_count(page) is %d content is %s \n",
				   __func__, addr, page_count(page), (char *)addr);
	} else {
		printk("%s()::page not found\n", __func__);
		page = pagecache_get_page(mapping, offset,
								 FGP_CREAT|FGP_FOR_MMAP,
								 vmf->gfp_mask);
		if (!page)
			return vmf_error(-ENOMEM);
		addr = (unsigned long)page_address(page);
		printk("%s()::got page addr is %16lx page_count(page) is %d content is %s \n",
				__func__, addr, page_count(page), (char *)addr);
		__SetPageUptodate(page);
		/* we have to call set_pages_array_uc *only* here
		* since if we call it on the page that is already
		* in the page cache, it would fail because
		* reserve_ram_pages_type underneath requires
		* existing type to be _PAGE_CACHE_MODE_WB in order
		* to perform any change. No idea why such limitation.
		* IMO reserve_ram_pages_type should be fixed to allow setting
		* the same type that is already set and not bail out
		* with error as currently */
		if (state->mode == SECRETMEM_UNCACHED)
			err = set_pages_array_uc(&page, 1);

	}

	if (state->mode == SECRETMEM_EXCLUSIVE)
		err = set_direct_map_invalid_noflush(page);
	else if (state->mode == SECRETMEM_UNCACHED)
		;
	else
		BUG();

	if (err) {
		printk("%s()::error found\n", __func__);
		/* in case of error dont try to delete pages 
		* that are already referenced, otherwise we
		* are going to BUG() */
		if (page_count(page) <= 2)
		delete_from_page_cache(page);
		return vmf_error(err);
	}

	addr = (unsigned long)page_address(page);

	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);

	vmf->page = page;
	return  0;
}

static void secretmem_close(struct vm_area_struct *vma)
{
	struct secretmem_state *state = vma->vm_file->private_data;
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct page *page;
	unsigned long addr;
	pgoff_t index;
					
	//printk("%s():: on vma\n", __func__);
	//dump_vma(vma);

	printk("%s():: state of page cache for this address_space mapping\n", __func__);
	xa_for_each(&mapping->i_pages, index, page) {
		get_page(page);
		lock_page(page);

		addr = (unsigned long)page_address(page);
		printk("%s()::page to be deleted addr is %16lx page_count(page) is %d content is %s \n",
				__func__, addr, page_count(page), (char *)addr);
		if (page_count(page) > 2){
			unlock_page(page);
			put_page(page);
			continue;
		}

		if (state->mode == SECRETMEM_EXCLUSIVE)
			set_direct_map_default_noflush(page);
		else if (state->mode == SECRETMEM_UNCACHED) {
			memset(addr, PAGE_POISON, PAGE_SIZE);
			printk("%s():: poisoned page to be deleted addr is %16lx page_count(page) is %d content is %s \n",
				__func__, addr, page_count(page), (char *)addr);
			set_pages_array_wb(&page, 1);
		} else
			BUG();

		__ClearPageDirty(page);
		delete_from_page_cache(page);

		unlock_page(page);
		put_page(page);
	}
}

static const struct vm_operations_struct secretmem_vm_ops = {
	.fault = secretmem_fault,
	.close = secretmem_close,
};

static int secretmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct secretmem_state *state = file->private_data;
	unsigned long mode = state->mode;

	if (!mode)
		return -EINVAL;

	/* do not support COW mappings for now */
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	switch (mode) {
		case SECRETMEM_UNCACHED:
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
			/* fallthrough */
		case SECRETMEM_EXCLUSIVE:
			vma->vm_ops = &secretmem_vm_ops;
			break;
		default:
			return -EINVAL;
	}

	return 0;
}

static long secretmem_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct secretmem_state *state = file->private_data;
	unsigned long mode = state->mode;

	if (mode)
		return -EINVAL;

	switch (cmd) {
		case MFD_SECRET_EXCLUSIVE:
			mode = SECRETMEM_EXCLUSIVE;
			break;
		case MFD_SECRET_UNCACHED:
			mode = SECRETMEM_UNCACHED;
			break;
		default:
			return -EINVAL;
	}

	state->mode = mode;

	return 0;
}

static int secretmem_release(struct inode *inode, struct file *file)
{
	   struct secretmem_state *state = file->private_data;

	   kfree(state);

	   return 0;
}

const struct file_operations secretmem_fops = {
	   .release        = secretmem_release,
	   .mmap           = secretmem_mmap,
	   .unlocked_ioctl = secretmem_ioctl,
	   .compat_ioctl   = secretmem_ioctl,
};

static bool secretmem_isolate_page(struct page *page, isolate_mode_t mode)
{
	   return false;
}

static int secretmem_migratepage(struct address_space *mapping,
								struct page *newpage, struct page *page,
								enum migrate_mode mode)
{
	   return -EBUSY;
}

static void secretmem_putback_page(struct page *page)
{
}

static const struct address_space_operations secretmem_aops = {
	   .migratepage    = secretmem_migratepage,
	   .isolate_page   = secretmem_isolate_page,
	   .putback_page   = secretmem_putback_page,
};

static struct vfsmount *secretmem_mnt;

struct file *secretmem_file_create(const char *name, unsigned int flags)
{
	   struct inode *inode = alloc_anon_inode(secretmem_mnt->mnt_sb);
	   struct file *file = ERR_PTR(-ENOMEM);
	   struct secretmem_state *state;

	   if (IS_ERR(inode))
			   return ERR_CAST(inode);

	   state = kzalloc(sizeof(*state), GFP_KERNEL);
	   if (!state)
			   goto err_free_inode;

	   file = alloc_file_pseudo(inode, secretmem_mnt, "secretmem",
								O_RDWR, &secretmem_fops);

	   if (IS_ERR(file))
			   goto err_free_state;

	   mapping_set_unevictable(inode->i_mapping);

	   inode->i_mapping->private_data = state;
	   inode->i_mapping->a_ops = &secretmem_aops;

	   file->private_data = state;

	   return file;

err_free_state:
	   kfree(state);
err_free_inode:
	   iput(inode);
	   return file;
}

static int secretmem_init_fs_context(struct fs_context *fc)
{
	   return init_pseudo(fc, SECRETMEM_MAGIC) ? 0 : -ENOMEM;
}

static struct file_system_type secretmem_fs = {
	   .name           = "secretmem",
	   .init_fs_context = secretmem_init_fs_context,
	   .kill_sb        = kill_anon_super,
};

static int secretmem_init(void)
{
	   int ret = 0;

	   secretmem_mnt = kern_mount(&secretmem_fs);
	   if (IS_ERR(secretmem_mnt))
			   ret = PTR_ERR(secretmem_mnt);

	   return ret;
}
fs_initcall(secretmem_init);


