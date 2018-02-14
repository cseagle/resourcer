/*
 *  This is a demo plugin
 *
 *  It is known to compile with
 *
 *   Visual C++
 *   cygwin g++/make
 *
 */

#define _CRT_SECURE_NO_WARNINGS

#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif  // USE_DANGEROUS_FUNCTIONS

#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#endif

//#include <windows.h>
//#include <windowsx.h>
//#include <commctrl.h>
#include <ida.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <netnode.hpp>

#include <stdint.h>

#include "image.h"
#include "sdk_versions.h"

//Some idasdk70 transition macros
#if IDA_SDK_VERSION >= 700

#define startEA start_ea 
#define endEA end_ea 

#define minEA min_ea
#define maxEA max_ea
#define ominEA omin_ea
#define omaxEA omax_ea
#define procName procname

#define get_flags_novalue(ea) get_flags(ea)
#define isEnum0(f) is_enum0(f)
#define isEnum1(f) is_enum1(f)
#define isStroff0(f) is_stroff0(f)
#define isStroff1(f) is_stroff1(f)
#define isOff0(f) is_off0(f)
#define isOff1(f) is_off1(f)
#define isOff(f, n) is_off(f, n)
#define isEnum(f, n) is_enum(f, n)
#define isStroff(f, n) is_stroff(f, n)
#define isUnknown(f) is_unknown(f)
#define getFlags(f) get_flags(f)

#define isStruct(f) is_struct(f)
#define isASCII(f) is_strlit(f)
#define do_unknown(a, f) del_items(a, f)
#define do_unknown_range(a, s, f) del_items(a, f, s)
#define isCode(f) is_code(f)

#define get_member_name2 get_member_name

#define put_many_bytes(a, b, s) put_bytes(a, b, s)
#define patch_many_bytes(a, b, s) patch_bytes(a, b, s)
#define get_many_bytes(a, b, s) get_bytes(b, s, a)
#define get_long(ea) get_dword(ea)

#define make_ascii_string create_strlit
#define ASCSTR_ULEN2 STRTYPE_LEN2_16
#define ASCSTR_UNICODE STRTYPE_C_16

#define do_data_ex(a, d, s, t) create_data(a, d, s, t)
#define doDwrd(a, l) create_dword(a, l)
#define doStruct(a, l, t) create_struct(a, l, t)

#define dwrdflag dword_flag

#define isEnabled(a) is_mapped(a)
#define isLoaded(a) is_loaded(a)

#define switchto_tform(w, f) activate_widget(w, f)
#define find_tform(c) find_widget(c)

#define get_segreg(a, r) get_sreg(a, r)
#define AskUsingForm_c ask_form
#define askfile_c ask_file
#define askyn_c ask_yn

#define alt1st altfirst
#define altnxt altnext

#define AST_DISABLE_FOR_FORM AST_DISABLE_FOR_WIDGET
#define AST_ENABLE_FOR_FORM AST_ENABLE_FOR_WIDGET
#define form_type widget_type
#define SETMENU_CTXIDA 0

#else //Some idasdk70 transition macros, we are pre 7.0 below

#define start_ea startEA
#define end_ea endEA

#define ev_add_cref add_cref
#define ev_add_dref add_dref
#define ev_del_cref del_cref
#define ev_del_dref del_dref
#define ev_oldfile oldfile
#define ev_newfile newfile
#define ev_auto_queue_empty auto_queue_empty

#define set_func_start func_setstart 
#define set_func_end func_setend

#define get_sreg(a, r) get_segreg(a, r)
#define get_dword(ea) get_long(ea)
#define get_bytes(b, s, a) get_many_bytes(a, b, s)

#define create_strlit make_ascii_string
#define STRTYPE_LEN2_16 ASCSTR_ULEN2
#define STRTYPE_C_16 ASCSTR_UNICODE

#define ask_form AskUsingForm_c
#define ask_file askfile_c
#define ask_yn askyn_c

#define altfirst alt1st
#define altnext altnxt

#define AST_DISABLE_FOR_WIDGET AST_DISABLE_FOR_FORM
#define AST_ENABLE_FOR_WIDGET AST_ENABLE_FOR_FORM
#define widget_type form_type

#endif //Some idasdk70 transition macros


//Resources organized as three deep tree: type/name/language

static const char rsrc_node_name[] = "$ RSRC netnode";
netnode rsrc_node(rsrc_node_name);

#define _RT_CURSOR 1
#define _RT_FONT 8
#define _RT_BITMAP 2
#define _RT_ICON 3
#define _RT_MENU 4
#define _RT_DIALOG 5
#define _RT_STRING 6
#define _RT_FONTDIR 7
#define _RT_ACCELERATOR 9
#define _RT_RCDATA 10
#define _RT_MESSAGETABLE 11
#define _RT_GROUP_CURSOR 12
#define _RT_GROUP_ICON 14
#define _RT_VERSION 16
#define _RT_DLGINCLUDE 17
#define _RT_PLUGPLAY 19
#define _RT_VXD 20
#define _RT_ANICURSOR 21
#define _RT_ANIICON 22
#define _RT_HTML 23
#define _RT_MANIFEST 24

#define RDIR_CHARACTERISTICS_DD 0  
#define RDIR_TIMESTAMP_DD 4  
#define RDIR_MAJOR_VERSION_DW 8  
#define RDIR_MINOR_VERSION_DW 10  
#define RDIR_NUM_NAMES_DW 12  
#define RDIR_NUM_ID_DW 14  

//whether first field is name or id is dictated by position in table
//from num_names or num_id above, all names preced all ids
#define RDIRENT_NAME_RVA_OR_ID_DD 0  
//high bit 0, this is data (resource data entry) rva, else subdir rva
#define RDIRENT_DATA_ENTRY_OR_SUBDIR_RVA_DD 4


#define RDATAENT_DATA_RVA_DD 0  
#define RDATAENT_SIZE_DD 4  
#define RDATAENT_CODEPAGE_DD 8  
#define RDATAENT_RESERVED_DD 12  

#define RDIRSTR_LEN_DW 0  
#define RDIRSTR_UNICODE_DW 2  

#define RSRC_TYPE_INDEX 100
#define RSRC_NAME_INDEX 101
#define RSRC_LANG_INDEX 102
#define RSRC_SIZE_INDEX 103

//pointer to til we use to extract function info
til_t *ti = NULL;

extern plugin_t PLUGIN;

void llx(qstring &s, uint64_t x) {
   s.sprnt("%x", (uint32_t)(x >> 32));
   s.cat_sprnt("%08x", (uint32_t)(x & 0xffffffff));
   while (s.size() > 1 && s[0] == '0') {
      s.remove(0, 1);
   }
}

const char *resourceTypeStr(unsigned int res) {
   if (res == _RT_CURSOR)
      return "RT_CURSOR";
   if (res == _RT_FONT)
      return "RT_FONT";
   if (res == _RT_BITMAP)
      return "RT_BITMAP";
   if (res == _RT_ICON)
      return "RT_ICON";
   if (res == _RT_MENU)
      return "RT_MENU";
   if (res == _RT_DIALOG)
      return "RT_DIALOG";
   if (res == _RT_STRING)
      return "RT_STRING";
   if (res == _RT_FONTDIR)
      return "RT_FONTDIR";
   if (res == _RT_ACCELERATOR)
      return "RT_ACCELERATOR";
   if (res == _RT_RCDATA)
      return "RT_RCDATA";
   if (res == _RT_MESSAGETABLE)
      return "RT_MESSAGETABLE";
   if (res == _RT_GROUP_CURSOR)
      return "RT_GROUP_CURSOR";
   if (res == _RT_GROUP_ICON)
      return "RT_GROUP_ICON";
   if (res == _RT_VERSION)
      return "RT_VERSION";
   if (res == _RT_DLGINCLUDE)
      return "RT_DLGINCLUDE";
   if (res == _RT_PLUGPLAY)
      return "RT_PLUGPLAY";
   if (res == _RT_VXD)
      return "RT_VXD";
   if (res == _RT_ANICURSOR)
      return "RT_ANICURSOR";
   if (res == _RT_ANIICON)
      return "RT_ANIICON";
   if (res == _RT_HTML)
      return "RT_HTML";
   if (res == _RT_MANIFEST)
      return "RT_MANIFEST";
   return NULL;
}

/*

char *getUnicodeString(ea_t addr) {
   unsigned int len = get_word(addr);
   addr += 2;
   char *res = new char[len + 1];
   for (int i = 0; i < len; i++) {
      res[i] = (char)get_word(addr);
      addr += 2;
   }
   res[len] = 0;
   return res;
}

void parseDataEntry(ea_t peImageBase, ea_t dataEntry, unsigned int &dataVA, unsigned int &dataSize, unsigned int &codePage) {
   char buf[256];
   if (!isLoaded(dataEntry)) {
      return;
   }
   dataVA = peImageBase + get_long(dataEntry);
   dataSize = get_long(dataEntry + 4);
   codePage = get_long(dataEntry + 8);
}

void parseDirectoryTable(ea_t peImageBase, ea_t rsrcBase, ea_t tableBase, ea_t id, HTREEITEM parent, int level) {
   char buf[256];
   HTREEITEM treeItem;
   TVINSERTSTRUCT tv;

   tv.hParent = parent;
   tv.hInsertAfter = TVI_LAST;
   tv.item.mask = TVIF_TEXT | TVIF_STATE;  // | TVIF_PARAM
   tv.item.state = TVIS_EXPANDED;
   tv.item.stateMask = TVIS_EXPANDED;
   //tv.item.lParam = xxx

   if (!isLoaded(tableBase)) {
      return;
   }
   //parse table fields
   unsigned int nameEntries = get_word(tableBase + 0xC);
   unsigned int idEntries = get_word(tableBase + 0xE);
   unsigned int totalEntries = nameEntries + idEntries;
   unsigned int timeStamp = get_long(tableBase + 4);
   if (nameEntries == 0xFFFF || idEntries == 0xFFFF) {
      return;
   }
   if (id & 0x80000000) {
      char *name = getUnicodeString(rsrcBase + (id & 0x7fffffff));
      snprintf(buf, sizeof(buf), "%*sResDir (%s) Entries:%2d (Named:%02.2d, ID:%02.2d) TimeDate:%08.8x\n",
               level * 3, "", name, totalEntries, nameEntries, idEntries, timeStamp);
      msg("%s", buf);

      tv.item.pszText = name;
      treeItem = (HTREEITEM)SendDlgItemMessage(resourceDlg, IDC_TREE1, TVM_INSERTITEM,
                                               0, (LPARAM) &tv);
      delete [] name;
   }
   else {
      const char *name = level == 1 ? resourceTypeStr(id) : NULL;
      snprintf(buf, sizeof(buf), "%*sResDir (%d) Entries:%2d (Named:%02.2d, ID:%02.2d) TimeDate:%08.8x\n",
               level * 3, "", id, totalEntries, nameEntries, idEntries, timeStamp);
      msg("%s", buf);
      snprintf(buf, sizeof(buf), "%d", id, level);
      if (name) {
         tv.item.pszText = name;
      }
      else {
         tv.item.pszText = buf;
      }
      treeItem = (HTREEITEM)SendDlgItemMessage(resourceDlg, IDC_TREE1, TVM_INSERTITEM,
                                               0, (LPARAM) &tv);
   }
   unsigned int entry = tableBase + 0x10;
   tv.hParent = treeItem;
   level++;
   for (unsigned int i = 0; i < totalEntries; i++) {
      unsigned int nameId = get_long(entry);
      unsigned int rva = get_long(entry + 4);
      unsigned int dataVA, dataSize, codePage;
      if (rva & 0x80000000) { //this is a nested table entry
         unsigned int nextTable = (rva & 0x7fffffff) + rsrcBase;
         parseDirectoryTable(peImageBase, rsrcBase, nextTable, nameId, treeItem, level);
      }
      else {  //this is a data entry
         unsigned int dataEntry = rsrcBase + rva;
         parseDataEntry(peImageBase, dataEntry, dataVA, dataSize, codePage);
         if (nameId & 0x80000000) {
            char *name = getUnicodeString(rsrcBase + (id & 0x7fffffff));
            snprintf(buf, sizeof(buf), "%s (Addr: 0x%08.8x, Size: %d)", name, dataVA, dataSize);
            tv.item.pszText = buf;
            treeItem = (HTREEITEM)SendDlgItemMessage(resourceDlg, IDC_TREE1, TVM_INSERTITEM,
                                                     0, (LPARAM) &tv);
            snprintf(buf, sizeof(buf), "%*sID: %s  DataEntryOffs: %08.8x\n", level * 3, "", name, dataEntry);
            delete [] name;
         }
         else {
            snprintf(buf, sizeof(buf), "%d (Addr: 0x%08.8x, Size: %d)", nameId, dataVA, dataSize);
            tv.item.pszText = buf;
            treeItem = (HTREEITEM)SendDlgItemMessage(resourceDlg, IDC_TREE1, TVM_INSERTITEM,
                                                     0, (LPARAM) &tv);
            snprintf(buf, sizeof(buf), "%*sID: %08.8x  DataEntryOffs: %08.8x\n", level * 3, "", nameId, dataEntry);
         }
         msg("%s", buf);
         snprintf(buf, sizeof(buf), "%*sDataVA: %08.8x  DataSize: %08.8x  CodePage: %d\n",
                  level * 3, "", dataVA, dataSize, codePage);
         msg("%s", buf);
      }
      entry += 8;
   }
}

*/

//resBase is rva of start of entire resource section
//resDir is rva o this resource table
//base is the image base VA
void walkResourceTree(ea_t resBase, ea_t resDir, ea_t base, int depth) {
   static int rsrcNum = 0;
   static ea_t path[4];
   static bool pathFlags[4];

#if (IDA_SDK_VERSION < 520)
   tid_t rd = til2idb(-1, "IMAGE_RESOURCE_DIRECTORY");      
#else
   tid_t rd = import_type(ti, -1, "IMAGE_RESOURCE_DIRECTORY");      
#endif

   doStruct(base + resDir, sizeof(_IMAGE_RESOURCE_DIRECTORY), rd);
   unsigned int numNamed = get_word(base + resDir + 12);
   unsigned int numEntries = numNamed + get_word(base + resDir + 14);
   ea_t resEntry = resDir + 16;

#if (IDA_SDK_VERSION < 520)
   tid_t rde = til2idb(-1, "IMAGE_RESOURCE_DIRECTORY_ENTRY");      
#else
   tid_t rde = import_type(ti, -1, "IMAGE_RESOURCE_DIRECTORY_ENTRY");      
#endif

   for (unsigned int i = 0; i < numEntries; i++) {
      char buf[256];
      doStruct(base + resEntry, sizeof(_IMAGE_RESOURCE_DIRECTORY_ENTRY), rde);
      unsigned int name_id = get_long(base + resEntry);
      if (i < numNamed) { //still in named entries portion of table
         pathFlags[depth] = true; // path component is named
         ea_t strAddr = base + resBase + (name_id & 0x7fffffff);
         path[depth] = strAddr;
         make_ascii_string(strAddr, 0, ASCSTR_ULEN2);
         unsigned int len = get_word(strAddr);
         qstrncpy(buf, "res_", 5);
#if (IDA_SDK_VERSION < 620)
         get_ascii_contents(strAddr + 2, len * 2, ASCSTR_UNICODE, buf + 4, sizeof(buf) - 4);
#elif IDA_SDK_VERSION < 700
         get_ascii_contents2(strAddr + 2, len * 2, ASCSTR_UNICODE, buf + 4, sizeof(buf) - 4);
else
         qstring utf8;
         get_strlit_contents(&utf8, strAddr + 2, len * 2, ASCSTR_UNICODE);
         qstrnpy(buf, utf8.c_str(), sizeof(buf));
#endif
         add_dref(base + resEntry, strAddr, (dref_t)(dr_O | XREF_USER));
      }
      else { //integer id
         path[depth] = name_id;
         pathFlags[depth] = false; // path component is numbered
         qsnprintf(buf, sizeof(buf), "res_%d", name_id);
      }
//      msg("Resource is named: %s\n", buf);
      unsigned int subEntry = get_long(resEntry + base + 4);
      ea_t dest;
      if (subEntry & 0x80000000) {
         dest = resBase + (subEntry & 0x7fffffff);
         walkResourceTree(resBase, dest, base, depth + 1);
      }
      else {
         //this is the actual resource pointer
         dest = resBase + subEntry;


#if (IDA_SDK_VERSION < 520)
         tid_t rdata = til2idb(-1, "IMAGE_RESOURCE_DATA_ENTRY");      
#else
         tid_t rdata = import_type(ti, -1, "IMAGE_RESOURCE_DATA_ENTRY");      
#endif

         doStruct(dest + base, sizeof(_IMAGE_RESOURCE_DATA_ENTRY), rdata);
         //actual rva data address is base relative, not rsrc relative
         nodeidx_t rsrcEA = base + get_long(base + dest);
         unsigned int rsrcSize = get_long(base + dest + 4);
         qsnprintf(buf, sizeof(buf), "resource size: %d bytes", rsrcSize);
         set_cmt(rsrcEA, buf, false);
         netnode rsrc(rsrcEA);
         rsrc_node.altset(rsrcNum++, rsrcEA, 'O');
         rsrc.altset(RSRC_SIZE_INDEX, get_long(base + dest + 4));
         for (int j = 0; j < 3; j++) {
            if (pathFlags[j]) {
               unsigned int len = get_word(path[j]);
#if (IDA_SDK_VERSION < 620)
               get_ascii_contents(path[j] + 2, len * 2, ASCSTR_UNICODE, buf, sizeof(buf));
#elif IDA_SDK_VERSION < 700
               get_ascii_contents2(path[j] + 2, len * 2, ASCSTR_UNICODE, buf, sizeof(buf));
else
               qstring utf8;
               get_strlit_contents(&utf8, path[j] + 2, len * 2, ASCSTR_UNICODE);
               qstrnpy(buf, utf8.c_str(), sizeof(buf));
#endif
               rsrc.supset(RSRC_TYPE_INDEX + j, buf);
            }
            else {
               rsrc.altset(RSRC_TYPE_INDEX + j, path[j]);
            }
         }
         add_dref(base + dest, rsrcEA, (dref_t)(dr_O | XREF_USER));
      }
      add_dref(base + resEntry + 4, base + dest, (dref_t)(dr_O | XREF_USER));
      set_name(base + dest, buf, SN_NOCHECK | SN_NOWARN);
      resEntry += sizeof(_IMAGE_RESOURCE_DIRECTORY_ENTRY);
   }
}

/*
//sections have been built by the time this is called.
//walk the resource tree and apply structure templates
void parseResources(IMAGE_NT_HEADERS *nt, ea_t rsrc) {
   char buf[256];
   unsigned int res_size, res_rva, res_fileoff, res_max;

   res_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
   res_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
   res_max = res_rva + res_size;
   if (res_rva) {
      msg("Resources present at %x\n", base + res_rva);
      walkResourceTree(res_rva, res_rva, base, 0);
   }
}
*/

//return the number of objects in the resource section
//object numbers are stored in the 'O' array of the rsrc_netnode
uint32 idaapi rsrc_sizer(void * /*obj*/) {
   uint32 count = 1;
   for (nodeidx_t i = rsrc_node.altval((nodeidx_t)count, 'O'); i; i = rsrc_node.altval((nodeidx_t)count, 'O')) {
      count++;
   }
   return count - 1;
}

//The width of each column
//address, name, type
//The headers for each column
static const char *headers[] = {"Address", "Type", "Name", "Language", "Size"};
static int cwidths[] = {20, 20, 30, 20, 10};
static uint32 ncols = sizeof(cwidths) / sizeof(uint32);

/*
 * obj Not used in this function
 * n indicates which line (1..n) of the display is being formated.
 *   if n is zero, the header line is being requested.
 * cells is a pointer to an array of character pointers. This array
 *       contains one pointer for each column in the chooser.  The output
 *       for each column should not exceed the corresponding width specified
 *       in the widths array.
 */
 void idaapi rsrc_getline2(void * /*obj*/, uint32 n, char* const* cells) {
   if (n == 0) {
      for (uint32 i = 0; i < ncols; i++) {
//         msg("%s, ", headers[i]);
         qstrncpy(cells[i], headers[i], MAXSTR);
      }
//      msg("\n");
   }
   else {
      uint32 count = 1;
      ea_t ea = (ea_t)rsrc_node.altval((nodeidx_t)n, 'O');
      if (ea) {
//         msg("%x: ", ea);
         qstring hex;
         llx(hex, ea);
         qsnprintf(cells[0], MAXSTR, ".rsrc:0x%s", hex.c_str());
         netnode obj(ea);

         unsigned int id = (unsigned int)obj.altval(RSRC_TYPE_INDEX);
         if (id) {
            const char *name = resourceTypeStr(id);
//            msg("ID: %d / 0x%x, ", id, id);
            if (name) {
               qsnprintf(cells[1], MAXSTR, "%s", name);
            }
            else {
               qsnprintf(cells[1], MAXSTR, "ID: %d / 0x%x", id, id);
            }
         }
         else {
            obj.supstr(RSRC_TYPE_INDEX, cells[1], MAXSTR);
//            msg("%s, ", cells[1]);
         }

         id = (unsigned int)obj.altval(RSRC_NAME_INDEX);
         if (id) {
//            msg("ID: %d / 0x%x, ", id, id);
            qsnprintf(cells[2], MAXSTR, "ID: %d / 0x%x", id, id);
         }
         else {
            obj.supstr(RSRC_NAME_INDEX, cells[2], MAXSTR);
//            msg("%s, ", cells[2]);
         }

         id = (unsigned int)obj.altval(RSRC_LANG_INDEX);
         if (id) {
//            msg("ID: %d / 0x%x, ", id, id);
            qsnprintf(cells[3], MAXSTR, "ID: %d / 0x%x", id, id);
         }
         else {
            obj.supstr(RSRC_LANG_INDEX, cells[3], MAXSTR);
//            msg("%s, ", cells[3]);
         }

         qsnprintf(cells[4], MAXSTR, "%u", (uint32_t)obj.altval(RSRC_SIZE_INDEX));
//         msg("%s\n", cells[4]);
      }
   }
}

void saveRangeToFile(const char * /*prompt*/, ea_t begin, uint32 len) {
   char *sf = askfile_c(1, NULL, "Save resource data");
   if (sf) {
      FILE *f = fopen(sf, "wb");
      if (f) {
         unsigned char buf[4096];
         uint32 need = len < sizeof(buf) ? len : sizeof(buf);
         uint32 saved = 0;
         while (need > 0 && get_many_bytes(begin + saved, buf, need)) {
            fwrite(buf, need, 1, f);
            saved += need;
            uint32 diff = len - saved;
            need = diff < sizeof(buf) ? diff : sizeof(buf);
         }
         fclose(f);
      }
   }
}

static uint32 cb_cmd = 0;

uint32 idaapi cb_save_resource(void * /*obj*/, uint32 n) {
   cb_cmd = 2;
   ea_t ea = (ea_t)rsrc_node.altval((nodeidx_t)n, 'O');
   msg("save_resource called\n");
   if (ea) {
      netnode obj(ea);
      uint32 sz = (uint32)obj.altval(RSRC_SIZE_INDEX);
      saveRangeToFile("Save resource data", ea, sz);
   }   
   return 1;  //success   
}

void idaapi cb_jump_resource(void * /*obj*/, uint32 n) {
   msg("Jump to resource(..., %d)\n", n);
   ea_t ea = (ea_t)rsrc_node.altval((nodeidx_t)n, 'O');
   if (ea) {
      netnode obj(ea);
      jumpto(ea);
   }
   cb_cmd = 3;
}

//we don't get an n here, but update gets called 
//immediately after
void displayResource(ea_t ea) {
   qstring hex;
   llx(hex, ea);
   msg("displayResource called: %s\n", hex.c_str());
   netnode obj(ea);
   nodeidx_t id = obj.altval(RSRC_TYPE_INDEX);
   switch (id) {
      case _RT_CURSOR:
         break;
      case _RT_FONT:
         break;
      case _RT_BITMAP:
         break;
      case _RT_ICON:
         break;
      case _RT_MENU:
         break;
      case _RT_DIALOG:
         break;
      case _RT_STRING: {
         unsigned int len = get_word(ea);
         char *buf = new char[len + 5];
#if (IDA_SDK_VERSION < 620)
         get_ascii_contents(ea + 2, len * 2, ASCSTR_UNICODE, buf, len + 5);
#elif IDA_SDK_VERSION < 700
         get_ascii_contents2(ea + 2, len * 2, ASCSTR_UNICODE, buf, len + 5);
else
         qstring utf8;
         get_strlit_contents(&utf8, ea + 2, len * 2, ASCSTR_UNICODE);
         qstrnpy(buf, utf8.c_str(), sizeof(buf));
#endif
         msg("%s\n", buf);
         delete [] buf;
         break;
      }
      case _RT_FONTDIR:
         break;
      case _RT_ACCELERATOR:
         break;
      case _RT_RCDATA:
         break;
      case _RT_MESSAGETABLE:
         break;
      case _RT_GROUP_CURSOR:
         break;
      case _RT_GROUP_ICON:
         break;
      case _RT_VERSION:
         break;
      case _RT_DLGINCLUDE:
         break;
      case _RT_PLUGPLAY:
         break;
      case _RT_VXD:
         break;
      case _RT_ANICURSOR:
         break;
      case _RT_ANIICON:
         break;
      case _RT_HTML:
         break;
      case _RT_MANIFEST:
         break;
      case 0: {//string name
         char name[256];
         obj.supstr(RSRC_TYPE_INDEX, name, sizeof(name));
         break;
      }
      default:   //unknown type
         break;
   }
}

//we don't get an n here, but update gets called 
//immediately after
void idaapi cb_display_resource(void * /*obj*/, uint32 n) {
   msg("Resource real display resource(..., %u)\n", n);
   ea_t ea = (ea_t)rsrc_node.altval((nodeidx_t)n, 'O');
   if (ea) {
      displayResource(ea);
   }
}

/*
void idaapi dblclick_handler(TCustomControl *c, const place_t *p, int pos, int shift, void *ud) {
   msg("double click: %d, %d\n", p->lnnum, pos);
}
*/

//typedef uint32 idaapi chooser_cb_t(void *obj, uint32 n);

/*
   chooser_cb_t *del=NULL,
   void (idaapi*ins)(void *obj)=NULL,
   chooser_cb_t *update=NULL,
   void (idaapi*edit)(void *obj,uint32 n)=NULL,
   void (idaapi*enter)(void * obj,uint32 n)=NULL,
   void (idaapi*destroy)(void *obj)=NULL,
*/

#if IDA_SDK_VERSION >= 670

#define DISPLAY_NAME "resourcer:display"
//-------------------------------------------------------------------------
struct display_action_handler_t : public action_handler_t {
   virtual int idaapi activate(action_activation_ctx_t *ctx) {
      uint32 n = (uint32)ctx->chooser_selection.size();
      if (n == 1) {
         n = (uint32)ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
         cb_display_resource(NULL, n);
#else
         cb_display_resource(NULL, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
         return n;
      }
      return 0;
   }
   
   virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
      bool ok = ctx->form_type == BWN_CHOOSER;
      if (ok) {
         //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
         char name[MAXSTR];
         ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, "Resources", qstrlen("Resources"));
#else
         qstring title;
         ok = get_widget_title(&title, ctx->widget) && title == "Resources";
#endif
      }
      return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
   }
};
static display_action_handler_t display_action_handler;
static const action_desc_t display_action = ACTION_DESC_LITERAL(DISPLAY_NAME, "Display resources", &display_action_handler, NULL, NULL, -1);

#define SAVERES_NAME "resourcer:saveres"
//-------------------------------------------------------------------------
struct saveres_action_handler_t : public action_handler_t {
   virtual int idaapi activate(action_activation_ctx_t *ctx) {
      uint32 n = (uint32)ctx->chooser_selection.size();
      if (n == 1) {
         n = (uint32)ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
         return cb_save_resource(NULL, n);
#else
         return cb_save_resource(NULL, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
      }
      return 0;
   }

   virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
      bool ok = ctx->form_type == BWN_CHOOSER;
      if (ok) {
         //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
         char name[MAXSTR];
         ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, "Resources", qstrlen("Resources"));
#else
         qstring title;
         ok = get_widget_title(&title, ctx->widget) && title == "Resources";
#endif
      }
      return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
   }
};
static saveres_action_handler_t saveres_action_handler;
static const action_desc_t saveres_action = ACTION_DESC_LITERAL(SAVERES_NAME, "Save resource", &saveres_action_handler, NULL, NULL, -1);

#define JUMPRES_NAME "resourcer:jumpres"
//-------------------------------------------------------------------------
struct jumpres_action_handler_t : public action_handler_t {
   virtual int idaapi activate(action_activation_ctx_t *ctx) {
      uint32 n = (uint32)ctx->chooser_selection.size();
      if (n == 1) {
         n = (uint32)ctx->chooser_selection[0];
#if IDA_SDK_VERSION < 700
         cb_jump_resource(NULL, n);
#else
         cb_jump_resource(NULL, n + 1);  //hack because pre-7.0 choosers index from 1
#endif
         return n;
      }
      return 0;
   }

   virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
      bool ok = ctx->form_type == BWN_CHOOSER;
      if (ok) {
         //it's a chooser, now make sure it's the correct form
#if IDA_SDK_VERSION < 700
         char name[MAXSTR];
         ok = get_tform_title(ctx->form, name, sizeof(name)) && strneq(name, "Resources", qstrlen("Resources"));
#else
         qstring title;
         ok = get_widget_title(&title, ctx->widget) && title == "Resources";
#endif
      }
      return ok ? AST_ENABLE_FOR_FORM : AST_DISABLE_FOR_FORM;
   }
};
static jumpres_action_handler_t jumpres_action_handler;
static const action_desc_t jumpres_action = ACTION_DESC_LITERAL(JUMPRES_NAME, "Jump to resource", &jumpres_action_handler, NULL, NULL, -1);
#endif

#if IDA_SDK_VERSION < 700

void configChooser() {
   choose2(0, -1, -1, -1, -1, NULL, 9, (const int*)cwidths, rsrc_sizer, rsrc_getline2, "Resources", -1);
/*
   TCustomControl *viewer = get_current_viewer();
   set_custom_viewer_handler(viewer, CVH_DBLCLICK, dblclick_handler);
*/   
}
#else
//-------------------------------------------------------------------------
struct resource_chooser_t : public chooser_t {
public:
   // this object must be allocated using `new`
   resource_chooser_t();

  // function that is used to decide whether a new chooser should be opened
  // or we can use the existing one.
  // The contents of the window are completely determined by its title
   virtual const void *get_obj_id(size_t *len) const {
      *len = strlen(title);
      return title;
   }

   // function that returns number of lines in the list
   virtual size_t idaapi get_count() const {
      return rsrc_sizer(NULL);
   }

   // function that generates the list line
   virtual void idaapi get_row(qstrvec_t *cols, int *icon_, chooser_item_attrs_t *attrs, size_t n) const;

   virtual cbret_t enter(size_t n) {
      cb_jump_resource(NULL, (uint32)n + 1);
      return cbret_t();
   }

};

inline resource_chooser_t::resource_chooser_t() :
      chooser_t(CH_KEEP, qnumber(cwidths), cwidths, headers, "Resources") {
}

void idaapi resource_chooser_t::get_row(qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const {
   uint32 count = 1;
   ea_t ea = (ea_t)rsrc_node.altval((nodeidx_t)n + 1, 'O');
   qstrvec_t &cols = *cols_;
   qstrvec_t::iterator ci = cols.begin();

   if (ea) {
//         msg("%x: ", ea);
      qstring hex;
      llx(hex, ea);
      cols[0].sprnt(".rsrc:0x%s", hex.c_str());
      netnode obj(ea);

      unsigned int id = (unsigned int)obj.altval(RSRC_TYPE_INDEX);
      ci++;
      if (id) {
         const char *name = resourceTypeStr(id);
//            msg("ID: %d / 0x%x, ", id, id);
         if (name) {
            cols[1].sprnt("%s", name);
         }
         else {
            cols[1].sprnt("ID: %d / 0x%x", id, id);
         }
      }
      else {
         obj.supstr(ci, RSRC_TYPE_INDEX);
//            msg("%s, ", cells[1]);
      }

      id = (unsigned int)obj.altval(RSRC_NAME_INDEX);
      ci++;
      if (id) {
//            msg("ID: %d / 0x%x, ", id, id);
         cols[2].sprnt("ID: %d / 0x%x", id, id);
      }
      else {
         obj.supstr(ci, RSRC_NAME_INDEX);
//            msg("%s, ", cells[2]);
      }

      id = (unsigned int)obj.altval(RSRC_LANG_INDEX);
      ci++;
      if (id) {
//            msg("ID: %d / 0x%x, ", id, id);
         cols[3].sprnt("ID: %d / 0x%x", id, id);
      }
      else {
         obj.supstr(ci, RSRC_LANG_INDEX);
//            msg("%s, ", cells[3]);
      }

      cols[4].sprnt("%u", (uint32_t)obj.altval(RSRC_SIZE_INDEX));
//         msg("%s\n", cells[4]);
   }
}

static resource_chooser_t resource_chooser;

void configChooser() {
   resource_chooser.choose(chooser_t::NO_SELECTION);
}

#endif
void createSegment(ea_t start, unsigned int size, unsigned char *content, 
                   unsigned int clen, const char *name) {
   segment_t s;
   //create ida segment
   memset(&s, 0, sizeof(s));
   s.startEA = start;
   s.endEA = start + size;
   s.align = saRelPara;
   s.comb = scPub;
   s.perm = SEGPERM_WRITE | SEGPERM_READ;
   s.bitness = 1;
   s.type = SEG_DATA;
   s.color = DEFCOLOR;
   if (add_segm_ex(&s, name, "DATA", ADDSEG_QUIET | ADDSEG_NOSREG)) {
      if (content) {
         patch_many_bytes(s.startEA, content, clen ? clen : size);
      }
//      msg("segment created %x-%x\n", s.startEA, s.endEA);
   }
   else {
//      msg("seg create failed\n");
   }
}

FILE *getInputFile() {
   char buf[260];
#if (IDA_SDK_VERSION < 490)
   char *fname = get_input_file_path();
   FILE *f = fopen(fname, "rb");
#else
   get_input_file_path(buf, sizeof(buf));
   FILE *f = fopen(buf, "rb");
#endif
   if (f == NULL) {
      warning("Original input file not found.");
      char *fname = askfile_c(0, buf, "Select input file");
      if (fname) {
         f = fopen(buf, "rb");
      }
   }
   return f;
}

ea_t loadResources(FILE *f, _IMAGE_NT_HEADERS *pe, _IMAGE_SECTION_HEADER *sh) {
   unsigned int rsrcRVA = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
   if (rsrcRVA) {
      unsigned int rsrcSz = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
      unsigned int rsrcEnd = rsrcRVA + rsrcSz;
      for (int i = 0; i < pe->FileHeader.NumberOfSections; i++) {
         if (rsrcRVA >= sh[i].VirtualAddress && rsrcEnd <= (sh[i].VirtualAddress + sh[i].Misc.VirtualSize)) {
            ea_t rsrcBase = pe->OptionalHeader.ImageBase + rsrcRVA;
            segment_t *r = getseg(rsrcBase);
            if (r == NULL) {   //nothing loaded at rsrcBase address
               if (fseek(f, sh[i].PointerToRawData, SEEK_SET) == 0) {
                  unsigned char *rsrc = (unsigned char*)malloc(rsrcSz);
                  if (fread(rsrc, rsrcSz, 1, f) != 1)  {
                     free(rsrc);
                     break;
                  }
                  createSegment(rsrcBase, sh[i].Misc.VirtualSize, rsrc, rsrcSz, ".rsrc");
                  free(rsrc);
               }
            }
            return rsrcBase;
         }
      }
   }
   return 0;
}

//--------------------------------------------------------------------------
//
//      Initialize.
//
//      IDA will call this function only once.
//      If this function returns PLGUIN_SKIP, IDA will never load it again.
//      If this function returns PLUGIN_OK, IDA will unload the plugin but
//      remember that the plugin agreed to work with the database.
//      The plugin will be loaded again if the user invokes it by
//      pressing the hotkey or selecting it from the menu.
//      After the second load the plugin will stay on memory.
//      If this function returns PLUGIN_KEEP, IDA will keep the plugin
//      in the memory. In this case the initialization function can hook
//      into the processor module and user interface notification points.
//      See the hook_to_notification_point() function.
//
//      In this example we check the input file format and make the decision.
//      You may or may not check any other conditions to decide what you do:
//      whether you agree to work with the database or not.
//
int idaapi init(void) {
   if (inf.filetype == f_PE) {
      return PLUGIN_KEEP;
   }
   return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
//      Terminate.
//      Usually this callback is empty.
//      The plugin should unhook from the notification lists if
//      hook_to_notification_point() was used.
//
//      IDA will call this function when the user asks to exit.
//      This function won't be called in the case of emergency exits.

void idaapi term(void) {
}

//--------------------------------------------------------------------------
//
//      The plugin method
//
//      This is the main function of plugin.
//
//      It will be called when the user activates the plugin.
//
//              arg - the input argument, it can be specified in
//                    plugins.cfg file. The default is zero.
//
//

#if IDA_SDK_VERSION < 700
void idaapi run(int /*arg*/) {
#else
bool idaapi run(size_t /*arg*/) {
#endif
   if (ti == NULL) {
#if IDA_SDK_VERSION >= 700
      qstring errbuf;
      ti = load_til("mssdk.til", &errbuf);
#else
      char err[256];
      *err = 0; 
#if IDA_SDK_VERSION < 695
      char tilpath[260];
      get_tilpath(tilpath, sizeof(tilpath));
      ti = load_til(tilpath, "mssdk.til", err, sizeof(err));
#else
      ti = load_til2("mssdk.til", err, sizeof(err));
#endif
#endif
   }
   
   //This is where we need to do something interesting
   if (exist(rsrc_node)) {
   }
   else {
      netnode pe("$ PE header");
      ea_t peImageBase = pe.altval(0xFFFFFFFE);
      ea_t rsrcBase = 0;
      segment_t *r = get_segm_by_name(".rsrc");
      if (r == NULL) {
         if (askyn_c(ASKBTN_NO, "Resources do not appear to be loaded would you like to load them now?") == ASKBTN_YES) {
            FILE *f = getInputFile();
            if (f) {
               _IMAGE_DOS_HEADER dos;
               if (fread(&dos, sizeof(_IMAGE_DOS_HEADER), 1, f) != 1) {
                  //error
               }
               else {
                  if (fseek(f, dos.e_lfanew, SEEK_SET)) {
                     //error
                  }
                  else {
                     _IMAGE_NT_HEADERS nt;
                     if (fread(&nt, sizeof(nt), 1, f) != 1) {
                        //error
                     }
                     else {
                        _IMAGE_SECTION_HEADER *sect = new _IMAGE_SECTION_HEADER[nt.FileHeader.NumberOfSections];
                        if (fread(sect, sizeof(_IMAGE_SECTION_HEADER), nt.FileHeader.NumberOfSections, f) != nt.FileHeader.NumberOfSections) {
                           //error
                        }
                        else {
                           rsrcBase = loadResources(f, &nt, sect);
                        }
                        delete [] sect;
                     }
                  }
               }
               fclose(f);
            }
         }
      }
      else {
         rsrcBase = r->startEA;
      }
      if (rsrcBase) {
         qstring hex;
         rsrc_node.create(rsrc_node_name);
         llx(hex, rsrcBase);
         msg("Resources (VA: %s)\n", hex.c_str());
         walkResourceTree(rsrcBase - peImageBase, rsrcBase - peImageBase, peImageBase, 0);
      }
/*
      if (askaddr(&rsrcBase, "Enter address of top level resource directory")) {
         if (rsrcBase && isLoaded(rsrcBase)) {
            parseDirectoryTable(peImageBase, rsrcBase, rsrcBase, 0, 0, 0);
         }
      }
*/
   }

   configChooser();

#if IDA_SDK_VERSION >= 670
   register_action(display_action);
   register_action(saveres_action);
   register_action(jumpres_action);
#if IDA_SDK_VERSION <= 695
   TForm *form = find_tform("Resources");
#else
   TWidget *form = find_widget("Resources");
#endif
   attach_action_to_popup(form, NULL, DISPLAY_NAME);
   attach_action_to_popup(form, NULL, SAVERES_NAME);
   attach_action_to_popup(form, NULL, JUMPRES_NAME);
#endif

   //test for presence of rsrc_node
   //if not present do nothing until user runs plugin
   //if present config to open chooser window
#if IDA_SDK_VERSION >= 700
   return true;
#endif
}

//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "Resource parser";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Alt-F4";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  NULL,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  NULL,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
