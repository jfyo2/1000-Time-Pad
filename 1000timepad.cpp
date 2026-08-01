// (c) jfyo2 2026

#include <fstream>  
#include <iostream> 
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Text_Editor.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Input.H>       
#include <FL/Fl_Button.H>     
#include <FL/Fl_Return_Button.H>
#include <FL/Fl_Text_Buffer.H> 
#include <FL/Fl_ask.H>
#include <FL/Fl_Menu_Bar.H> 
#include <FL/Fl_Menu_Item.H> 
#include <FL/Fl_File_Chooser.H> 
#include <cerrno>
#include <cstring>
#include <windows.h>

#include "aes.h"
#include "PBKDF2.h"

int loading = 0; // tells us whether a new file is being loaded or not 
int changed = 0; // this will become 1 if we edit anything and don't save the file
char filename[256] = "Nameless File";

std::vector<std::string> recent_files;
const size_t MAX_RECENT_FILES = 10;
std::string recent_dat_file_path = "recents.dat"; // fallback default 

Fl_Text_Buffer *textbuf;
int sel_start, sel_end; // tracks selection in find/replace dialogue 
bool edited_since_find = false; // tracks whether text edited since last find 
bool cursor_visible = true; // used for blinking cursor 
bool currently_typing = false; 

char encrypt_mode[8];
int keysize = 128; // key size in bits for encryption/decryption

const int MIN_FONT_SIZE = 4;
const int MAX_FONT_SIZE = 256;

// track undo/redo history 
std::vector<std::string> undo_history;
std::vector<std::string> redo_history;


// DEBUG SCRIPT
// void print_undo_redo(const std::vector<std::string>& undo_hist, 
//                             const std::vector<std::string>& redo_hist) 
// {
//     std::cout << "\n================= UNDO / REDO DEBUG =================\n";
    
//     // Print Undo Stack
//     std::cout << "--- UNDO STACK (" << undo_hist.size() << " items) ---\n";
//     if (undo_hist.empty()) {
//         std::cout << "  (empty)\n";
//     } else {
//         for (size_t i = 0; i < undo_hist.size(); ++i) {
//             std::cout << "  [" << i << "] \"" << undo_hist[i] << "\"\n";
//         }
//     }

//     // Print Redo Stack
//     std::cout << "\n--- REDO STACK (" << redo_hist.size() << " items) ---\n";
//     if (redo_hist.empty()) {
//         std::cout << "  (empty)\n";
//     } else {
//         for (size_t i = 0; i < redo_hist.size(); ++i) {
//             std::cout << "  [" << i << "] \"" << redo_hist[i] << "\"\n";
//         }
//     }
    
//     std::cout << "======================================================\n\n";
// }


/* --- Declare all handler functions --- */
void text_changed(int pos, int nInserted, int nDeleted, int nRestyled, const char* deletedText, void* editorWindow);
void blink_cursor(void* data);

void window_close_confirm(Fl_Widget* widget, void* editorWindow);
void open_file_dialogue(Fl_Widget* w, void* data);
void save_file_dialogue(Fl_Widget* w, void* data);
void save_as_dialogue(Fl_Widget* w, void* data);
void new_file(Fl_Widget* w, void* data);
void open_file(char* newfile, int ipos);
void save_file(char *newfile);

void init_recents_path(const char* argv0);
void read_recent_files();
void redraw_recents_menu(Fl_Widget* w, void* data);
void add_recent_files(const std::string& filepath);
void clear_recents_menu(Fl_Widget* w, void* data);

void undo_edit(Fl_Widget* w, void* data);
void redo_edit(Fl_Widget* w, void* data);
int kf_custom_undo(int key, Fl_Text_Editor* ed);
int kf_custom_redo(int key, Fl_Text_Editor* ed);

void zoom_in(void* data);
void zoom_out(void* data);

void cut_cb(Fl_Widget* w, void* data);
void copy_cb(Fl_Widget* w, void* data);
void paste_cb(Fl_Widget* w, void* data);
void delete_cb(Fl_Widget* w, void* data);
void select_all_cb(Fl_Widget* w, void* data);

void encrypt_decrypt_text(Fl_Widget* w, void* data); 
void show_encrypt_window(Fl_Widget* w, void* data); 
void show_decrypt_window(Fl_Widget* w, void* data); 
void cancel_encrypt_cb(Fl_Widget* w, void* data); 
void explain_encryption(Fl_Widget* w, void* data); 
std::string add_whitespace(const std::string &s);
std::string remove_whitespace(const std::string &s);

void cb_128(Fl_Widget* w, void* data);
void cb_192(Fl_Widget* w, void* data);
void cb_256(Fl_Widget* w, void* data);

void show_findandreplace(Fl_Widget* w, void* data);  
void find_previous_cb(Fl_Widget* w, void* data);
void find_next_cb(Fl_Widget* w, void* data); 
void replace_selection_cb(Fl_Widget* w, void* data); 
void replace_all_cb(Fl_Widget* w, void* data); 
void replace_cancel_cb(Fl_Widget* w, void* data); 

int index_of_selection(void* data);
int count_total_occurrences(void* data);

void update_count(void* data);
void currently_typing_updater(void* data);

void toggle_wordwrap_cb(Fl_Widget* w, void* data);
void toggle_linenumbers_cb(Fl_Widget* w, void* data);

/* --- Editor Class --- */

// The basic GUI is based loosely on the tutorial found at https://www.fltk.org/doc-1.1/editor.html#editor
// First we arrange all various features of the window 
class EditorWindow : public Fl_Double_Window {
    public: 
        // will write full constructor later, once we've set up all the menus and nonsense 
        EditorWindow(int w, int h, const char* title);
        // destructor is currently empty 
        ~EditorWindow() {}

        // stuff for find and replace dialogue 
        Fl_Window *replace_dlg;
        Fl_Input *find_text;
        Fl_Input *replace_with_text;
        Fl_Button *find_previous;
        Fl_Button *find_next;
        Fl_Button *replace_selection;
        Fl_Button *replace_all;
        Fl_Button *replace_cancel;
        Fl_Box *match_count_label;

        // stuff for encrypt/decrypt dialogue 
        Fl_Window *encrypt_dlg;
        Fl_Input *password_input;
        Fl_Button *encrypt;
        Fl_Button *cancel_encrypt;
        Fl_Choice *keybits; 
        Fl_Button *encrypt_explain;

        Fl_Text_Editor *editor;
        Fl_Menu_Bar* menu;
        bool is_undo_redo_action; // flag to prevent infinite callback loops 
        
        // we want to enable zooming in/out by CTRL + mouse scrollwheel
        // to do this we need to override the handle 
        int handle(int event) override {
            if (event == FL_MOUSEWHEEL && (Fl::event_state() & FL_CTRL)) {
                int scroll_direction = Fl::event_dy();

                if (scroll_direction < 0) // note <0 means scrolling up 
                    zoom_in(this);
                else if (scroll_direction > 0)
                    zoom_out(this);
                return 1;
            }
            return Fl_Double_Window::handle(event);
        }
    
};

/* --- Editor Constructor --- */

EditorWindow::EditorWindow(int w, int h, const char* title) 
    : Fl_Double_Window(w, h, title), is_undo_redo_action(false) {

    // Draw the text editor and the buffer in the window
    textbuf = new Fl_Text_Buffer();
    editor = new Fl_Text_Editor(0, 30, w, h - 30);
    editor->buffer(textbuf);
    editor->textfont(FL_COURIER); // add a new font 

    // set base initial state
    undo_history.push_back("");

    textbuf->add_modify_callback(text_changed, this);

    Fl_Menu_Item menuitems[] = {
        { "File", 0, 0, 0, FL_SUBMENU },
            { "New", FL_CTRL + 'n', new_file, 0, 0 },
            { "Open", FL_CTRL + 'o', open_file_dialogue, 0, 0 },
            { "Open Recent", FL_CTRL + FL_SHIFT + 'o', 0, 0, FL_SUBMENU },
                { 0 },
            { "Save", FL_CTRL + 's', save_file_dialogue, 0, 0 },
            { "Save As", FL_CTRL + FL_SHIFT + 's', save_as_dialogue, 0, 0 },
            { 0 },

        { "Edit", 0, 0, 0, FL_SUBMENU },
            { "Undo", FL_CTRL + 'z', undo_edit, 0, 0 },
            { "Redo", FL_CTRL + 'y', redo_edit, 0, FL_MENU_DIVIDER },
            { "Cut", FL_CTRL + 'x', cut_cb, 0, 0 },
            { "Copy", FL_CTRL + 'c', copy_cb, 0, 0 },
            { "Paste", FL_CTRL + 'v', paste_cb, 0, 0 },
            { "Delete", FL_CTRL + FL_Delete, delete_cb, 0, 0 },
            { "Select All", FL_CTRL + 'a', select_all_cb, 0, FL_MENU_DIVIDER },
            { "Find and Replace", FL_CTRL + 'f', show_findandreplace, 0, 0 },
            { 0 },

        { "View", 0, 0, 0, FL_SUBMENU },
            {"Zoom In", FL_CTRL + FL_SHIFT + '+', [](Fl_Widget* w, void* v) { zoom_in(v); }, 0, 0 },
            {"Zoom Out", FL_CTRL + FL_SHIFT + '-', [](Fl_Widget* w, void* v) { zoom_out(v); }, 0, FL_MENU_DIVIDER },
            { "Word Wrap", 0, toggle_wordwrap_cb, 0, FL_MENU_TOGGLE },
            { "Line Numbers", 0, toggle_linenumbers_cb, 0, FL_MENU_TOGGLE },
            { 0 },
        { "Encryption", 0, 0, 0, FL_SUBMENU }, 
            {"Encrypt Text", 0, show_encrypt_window, 0, 0 },
            {"Decrypt Text", 0, show_decrypt_window, 0, 0 },
            { 0 },
    { 0 }
    };

    menu = new Fl_Menu_Bar(0, 0, w, 30);
    menu->user_data(this); 
    menu->copy(menuitems, this);

    // // add recent files for opening
    // if (recent_files.empty()) {
    //     menu->add("No recent files", 0, nullptr, nullptr, FL_MENU_INACTIVE); 
    // } else {
    //     for (const std::string &file : recent_files) {
    //         // remove path from filename (e.g. C:/users/bob/bob.txt becomes bob.txt)
    //         std::string filename_nopath = std::filesystem::path(file).filename().string();
    //         std::string menu_path = "File/Open Recent/" + filename_nopath;

    //         menu->add(
    //             menu_path.c_str(), 0, 
    //             [](Fl_Widget* w, void* v) {
    //                 char* target_file = static_cast<char*>(v);
    //                 if (target_file) {
    //                     open_file(target_file, -1);
    //                 }
    //             }, 
    //             (void*)file.c_str(),
    //             0
    //         );
    //     }
    // }
    // add clear recents button 
    // menu->add("File/Open Recent/Clear Recents", 0, clear_recents_menu, (void*)this, 0);
    // menu->redraw();

    redraw_recents_menu(nullptr, this);

    // Remove default Ctrl+Z key binding here inside the constructor
    // and use custom undo function 
    editor->remove_key_binding('z', FL_CTRL);
    editor->add_key_binding('z', FL_CTRL, kf_custom_undo);
    editor->remove_key_binding('y', FL_CTRL);
    editor->add_key_binding('y', FL_CTRL, kf_custom_redo);
    editor->remove_key_binding('f', FL_CTRL);
    editor->add_key_binding('y', FL_CTRL, kf_custom_redo);

    
    // Set up find and replace dialogue 
    replace_dlg = new Fl_Window(480, 105, "Find and Replace");
    find_text = new Fl_Input(70, 10, 200, 25, "Find:");
    replace_with_text = new Fl_Input(70, 40, 200, 25, "Replace:");
    find_previous = new Fl_Button(400, 10, 30, 30, "←");
    find_next = new Fl_Button(435 , 10, 30, 30, "→");
    replace_selection = new Fl_Button(175, 70, 120, 25, "Replace Selection");
    replace_all = new Fl_Button(300, 70, 100, 25, "Replace All");
    replace_cancel = new Fl_Button(405, 70, 60, 25, "Cancel");
    match_count_label = new Fl_Box(315, 10, 70, 25, "No Results");

    find_previous->callback(find_previous_cb, this);
    find_next->callback(find_next_cb, this);
    replace_selection->callback(replace_selection_cb, this);
    replace_all->callback(replace_all_cb, this);
    replace_cancel->callback(replace_cancel_cb, this);

    replace_dlg->set_non_modal();
    replace_dlg->end();


    // set up encrypt/decrypt dialogue 
    encrypt_dlg = new Fl_Window(280, 135, "Encrypt Text");
    password_input = new Fl_Input(70, 10, 200, 25, "Password:");
    keybits = new Fl_Choice(70, 50, 100, 25, "Key Size:"); 
    encrypt = new Fl_Button(140, 100, 60, 25, encrypt_mode);
    cancel_encrypt = new Fl_Button(210, 100, 60, 25, "Cancel");
    encrypt_explain = new Fl_Button(10, 100, 25, 25, "?");
    Fl_Menu_Item keys[] = {
        { "128-bit", 0, cb_128, 0, 0 },
        { "192-bit", 0, cb_192, 0, 0 },
        { "256-bit", 0, cb_256, 0, 0 },
        { 0 }
    };
    keybits->user_data(this); 
    keybits->copy(keys, this);

    encrypt->callback(encrypt_decrypt_text, this);
    cancel_encrypt->callback(cancel_encrypt_cb, this);
    encrypt_explain->callback(explain_encryption, this);

    encrypt_dlg->set_non_modal();
    encrypt_dlg->end();


    editor->user_data(this);
    end();
    resizable(editor);
} 

// class File {
//     public: 
//         std::string name; // file name without a path
//         std::string path; // full file path 

//         File(std::string path_to_file) {
//             this->name = std::filesystem::path(path_to_file).filename().string();
//             this->path = path_to_file;
//         }

//         ~File();
// };


int main(int argc, char **argv) {
    // needed for full unicode support on win
    #ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #endif

    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif
    // Hide the automatic console window
    //ShowWindow(GetConsoleWindow(), SW_HIDE);

    // read recent files
    init_recents_path(argv[0]);
    read_recent_files();


    EditorWindow win(800, 600, "Nameless File - Thousand Time Pad");
    win.show(argc, argv);
    Fl::add_timeout(0.5, blink_cursor, &win);
    Fl::add_timeout(0.75, currently_typing_updater, &win);
    return Fl::run();
}





/* --- Function Implementations --- */

// Helper function to safely retrieve EditorWindow pointer
static EditorWindow* get_window(Fl_Widget* w, void* data) {
    // we use if guard clauses to ensure that w/data do not point to nullptr
    if (data) return static_cast<EditorWindow*>(data);
    if (w && w->user_data()) return static_cast<EditorWindow*>(w->user_data());
    return nullptr;
}

// check if text was changed 
void text_changed(int pos, int nInserted, int nDeleted, int nRestyled, const char* deletedText, void* editorWindow) {
    EditorWindow* window = static_cast<EditorWindow*>(editorWindow);
    // guard clause to check not nullptr 
    if (!window) return;

    if (loading) return; // skip if changes were only due to loading
    if (window->is_undo_redo_action) return; // skip recording history if change was due to undo/redo
    // this is to stop us getting in an infinite loop of undos/redos


    // Check if text was changed and do some things 
    if (nInserted == 0 && nDeleted == 0) return;

    changed = 1; // track changes in general
    edited_since_find = true; // track changes since last use of ctrl-f
    // make sure we perma show the cursor whilst typing is taking place 
    // (changes to blinking after a period of inactivity by currently_typing_updater())
    currently_typing = true;
    window->editor->show_cursor(true);

    update_count(window);

    // char newlabel[260];
    // std::strcpy(newlabel, filename);
    // std::strcpy(newlabel, "* - Thousand Time Pad");
    std::string editedsuffix = "* - Thousand Time Pad";
    std::string title = filename + editedsuffix;
    if (window) window->label(title.c_str());

    char* raw_text = textbuf->text();
    std::string current_text(raw_text ? raw_text : "");
    if (raw_text) free(raw_text);

    // next we limit the stack size to prevent unbounded memory usage 
    if (undo_history.size() >= 50) {
        undo_history.erase(undo_history.begin());
    }

    // record state to undo history if it differs from the current top 
    if (undo_history.empty() || undo_history.back() != current_text) {
        undo_history.push_back(current_text);
        // clear redo history because a new edit removes the redo path
        redo_history.clear();

        // FOR DEBUGGING 
        //print_undo_redo(undo_history, redo_history);
    }
}

// make currently_typing false every 1s (it gets set to true whenever an edit is made) 
void currently_typing_updater(void* data) {
    EditorWindow* window = get_window(nullptr, data);
    if (!window) return;

    currently_typing = false;

    Fl::repeat_timeout(0.75, currently_typing_updater, data);
}

 
// blink cursor when not typing 
void blink_cursor(void* data) {
    EditorWindow* window = get_window(nullptr, data);
    if (!window) return;

    if (!currently_typing) {
        cursor_visible = !cursor_visible;
        window->editor->show_cursor(cursor_visible);
        
    }
    Fl::repeat_timeout(0.5, blink_cursor, data); // reschedule every 0.5s for a blink effect
}

// check if there are unsaved changes and puts up a save dialogue
// returns 0 if save clicked, 1 if no change/discard changes clicked, 2 if user wants to cancel 
int check_unsaved(void) {
    if (!changed) return 1;

    int choice = fl_choice("The file has been modified. Would you like to save it now?", "Save", "Discard Changes", "Cancel");

    return choice;
}

void new_file(Fl_Widget* widget, void* editorWindow) {
    // first confirm save 
    if (changed) {
        int savecheck = check_unsaved();

        if (savecheck == 0) {
            save_file(filename);
        }
        else if (savecheck == 2) {
            return;
        }
    }

    // set text to contain nothing
    textbuf->text("");

    // reset file tracking variables
    filename[0] = '\0';
    changed = 0;

    EditorWindow* window = (EditorWindow*) editorWindow;
    if (window) {
        window->label("Nameless File - Thousand Time Pad");
    }

    textbuf->call_modify_callbacks();
}


// Show a confirm dialogue if the user tries to close the window before saving
void window_close_confirm(Fl_Widget* widget, void* editorWindow) {
    // data from window
    EditorWindow* window = get_window(widget, editorWindow);
    if (!window) return;
    // setup new confirm dialogue widget 
    EditorWindow *confirmWidget = (EditorWindow*) widget;

    if (changed) {
        int choice = check_unsaved();

        if (choice == 0) {
            save_file(filename);
        }
        else if (choice == 1) {
            // FIX: Ensure window is not null before accessing hide
            if (window) window->hide();
        }
        // if choice == 2 do nothing, so we omit this
    }
    else {
        if (window) window->hide();
    }
}


// Open file
// note: ipos represents the character index in the text editor 
// if ipos is 0, it means beginning, ipos is 50, it means after the 50th character etc.
// but ipos being -1 means we are opening a new file, not pasting text into an existing one 
void open_file(char* newfile, int ipos) {
    // we need to distinguish between pasting text and just loading a new file. 
    // in particular we only want to mark the file as changed if we are 
    // pasting stuff in, but not if we open a new file 
    loading = 1;
    changed = (ipos != -1);

    int errcheck;
    if (ipos == -1) {
        strcpy(filename, "");
        errcheck = textbuf->loadfile(newfile);
    }
    else {
        errcheck = textbuf->insertfile(newfile, ipos);
    }

    if (errcheck) {
        fl_alert("Error reading from file \'%s\':\n%s.", newfile, strerror(errno));
    }
    else {
        if (ipos == -1) strcpy(filename, newfile);
    }
    // add to recents, remove anything after 10th 
    add_recent_files(filename);

    // reset undo/redo history
    undo_history.clear();
    redo_history.clear();

    // reset loading flag 
    loading = 0;
    textbuf->call_modify_callbacks();
}

void init_recents_path(const char* argv0) {
    namespace fs = std::filesystem;
    fs::path exe_path = fs::absolute(argv0).parent_path();
    recent_dat_file_path = (exe_path / "recents.dat").string();
}

// read recent files from recents.dat to std::string recent_files
void read_recent_files() {
    std::ifstream recents_dat(recent_dat_file_path);
    if (!recents_dat.is_open()) return;

    recent_files.clear();

    std::string line;
    while (getline(recents_dat, line)) {
        // Ignore empty lines
        if (line.empty()) continue;

        recent_files.push_back(line);

        if (recent_files.size() >= MAX_RECENT_FILES) break;
    }
    recents_dat.close();
}

void save_recents_list() {
    // save recents data to a file 
    // wipe file if recents is empty 
    if (recent_files.empty()) {
        fclose(fopen(recent_dat_file_path.c_str(), "w"));
    } else {
        std::ofstream out(recent_dat_file_path.c_str());
        for (const auto &file : recent_files) {
            out << file << "\n";
        }
        out.close();
    }
}

void add_recent_files(const std::string& filepath) {
    if (filepath.empty()) return;

    // search if file is already in recent_files, if so, remove 
    auto find = std::find(recent_files.begin(), recent_files.end(), filepath);
    if (find != recent_files.end()) recent_files.erase(find);

    // insert filepath at head 
    recent_files.insert(recent_files.begin(), filepath);
    
    // drop last item if we go over MAX_RECENT_FILES
    if (recent_files.size() > MAX_RECENT_FILES) {
        recent_files.pop_back();
    }

    save_recents_list();
}
//
// Writes file to the address at newfile.
void save_file(char *newfile) {
    if (textbuf->savefile(newfile))
        fl_alert("Error writing to file \'%s\':\n%s.", newfile, strerror(errno));
    else {
        strcpy(filename, newfile);
        changed = 0;
        // Find main window to clean up the title asterisk
        Fl_Window* win = Fl::first_window();
        
        std::string suffix = " - Thousand Time Pad";
        std::string title = filename + suffix;
        if (win) win->label(title.c_str());
    }
    textbuf->call_modify_callbacks();
}



// useful 
struct RecentFileEntry {
    std::string filepath;
    EditorWindow* win;
};

// void* data should accept a RecentFileEntry
void open_recent_file_cb(Fl_Widget* w, void* data) {
    RecentFileEntry* entry = static_cast<RecentFileEntry*>(data);
    if (entry) {
        if (changed) {
            int savecheck = check_unsaved();

            if (savecheck == 0) {
                save_file(filename);
            }
            else if (savecheck == 2) {
                return;
            }
        }
        open_file(const_cast<char*>(entry->filepath.c_str()), -1);
        add_recent_files(entry->filepath);
        entry->win->label(entry->filepath.c_str());
        strcpy(filename, entry->filepath.c_str());
        undo_history.clear();
        redo_history.clear();
        save_recents_list();
        redraw_recents_menu(w, entry->win);
    }
}



void redraw_recents_menu(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win) return;


    // find location index of submenu
    // int index = -1;
    // for (int i = 0; i < win->menu->size(); i++) {
    //     const Fl_Menu_Item* item = &(win->menu->menu()[i]);
    //     if (item->text && strcmp(item->text, "Open Recent") == 0) {
    //         index = i;
    //         break;
    //     }
    // }
    int index = win->menu->find_index("File/Open Recent");

    if (index >= 0) {
        win->menu->clear_submenu(index);
    }

    static std::vector<RecentFileEntry> recent_entries_storage;
    recent_entries_storage.clear(); 
    recent_entries_storage.reserve(recent_files.size()); 

    if (recent_files.empty()) {
        win->menu->add("File/Open Recent/No recent files", 0, nullptr, nullptr, FL_MENU_INACTIVE);
    } else {        
        for (const auto &file : recent_files) {
            // remove path from filename (e.g. C:/users/bob/bob.txt becomes bob.txt)
            std::string filename_nopath = std::filesystem::path(file).filename().string();

            std::string menu_item_path = "File/Open Recent/" + filename_nopath;

            // we want to pass both win and file to the next callback, which due to the fact that FLTK only accepts callbacks with input (Fl_Widget* w, void* v) is a bit annoying. We make a small struct to deal with this: 
            
            recent_entries_storage.push_back({ file, win });
            RecentFileEntry* entry_ptr = &recent_entries_storage.back();

            win->menu->add(
                menu_item_path.c_str(), 
                0, 
                open_recent_file_cb,
                (void*)entry_ptr, // user_data pointer (valid while win->recent_files lives)
                0
            );
        }
    }
    // we need to manually pass (void*) win here because unlike when we set up the menu, there we used menu->user_data(this); to automatically pass in the EditorWindow*. But add() overrides the user_data assignment. 
    win->menu->add("File/Open Recent/Clear Recents", 0, clear_recents_menu, (void*)win, 0);
    win->menu->redraw();
}


void clear_recents_menu(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win) return;

    recent_files.clear();
    redraw_recents_menu(w, data);
}


// Menu wrappers to pass the choices into the underlying file engine
void open_file_dialogue(Fl_Widget* w, void* data) {
    // data from window
    EditorWindow* win = get_window(w, data);
    if (!win) return;

    // if we try to open a file without saving the previous one, 
    // before opening, check if we want to save the previous file
    if (changed) {
        int savecheck = check_unsaved();

        if (savecheck == 0) {
            save_file(filename);
        }
        else if (savecheck == 2) {
            return;
        }
    }

    char *newfile = fl_file_chooser("Open File?", "*", filename);
    if (newfile != NULL) open_file(newfile, -1);

    // update window label 
    std::string suffix = " - Thousand Time Pad";
    std::string title = filename + suffix;
    if (win) win->label(title.c_str());

    // add files -- and add a placeholder if empty 
    add_recent_files(filename);
    // redraw recent files menu 
    redraw_recents_menu(w, data);    
}

void save_file_dialogue(Fl_Widget* w, void* data) {
    if (filename[0] == '\0' || strcmp(filename, "Nameless File") == 0) {
        // No file name exists yet, act like "Save As"
        char *newfile = fl_file_chooser("Save File As?", "*", filename);
        if (newfile != NULL) save_file(newfile);

        // update the recents menu
        add_recent_files(newfile);
        redraw_recents_menu(w, data);
    } 
    else {
        save_file(filename);
    }
}

// we copy the save as functionality from save_file_dialogue 
void save_as_dialogue(Fl_Widget* w, void* data) {
    char *newfile = fl_file_chooser("Save File As?", "*", filename);
    if (newfile != NULL) save_file(newfile);

    add_recent_files(newfile);
    redraw_recents_menu(w, data);
}


void undo_edit(Fl_Widget* w, void* data) {
    EditorWindow* window = get_window(w, data);
    // do nothing if there are no edits 
    if (!window || undo_history.size() <= 1) return;

    // prevent text_changed from recording the undo edit as a new thing in the history 
    window->is_undo_redo_action = true;

    // instead we alter the history manually 
    // add the last entry of undo_history to the end of redo_history
    // and delete the last entry of undo_history
    std::string currentstate = undo_history.back();
    std::string previousstate = undo_history.end()[-2];

    // FOR DEBUGGING 
    /*
    std::cout << "This is the value of currentstate:";
    std::cout << currentstate;
    std::cout << "\nThis is the value of previousstate:";
    std::cout << previousstate;
    */

    redo_history.push_back(currentstate);
    undo_history.pop_back();
    //std::cout << "\nPush/pop back complete";

    // restore previous text
    textbuf->text(previousstate.c_str());

    window->is_undo_redo_action = false;

    // FOR DEBUGGING 
    //print_undo_redo(undo_history, redo_history);
}


void redo_edit(Fl_Widget* w, void* data) {
    EditorWindow* window = get_window(w, data);
    if (!window || redo_history.empty()) return;

    // rest of the code will be basically the same as undo_edit
    window->is_undo_redo_action = true;
    std::string state = redo_history.back();

    // FOR DEBUGGING
    /*
    std::cout << "This is the value of state:";
    std::cout << state;
    */

    redo_history.pop_back();
    undo_history.push_back(state);
    textbuf->text(state.c_str());
    window->is_undo_redo_action = false;

    // FOR DEBUGGING 
    //print_undo_redo(undo_history, redo_history);
}


int kf_custom_undo(int key, Fl_Text_Editor* ed) {
    EditorWindow* win = (EditorWindow*)ed->user_data();
    if (win) {
        undo_edit(ed, win);
    }
    return 1; // Return 1 to indicate the key event was handled
}

int kf_custom_redo(int key, Fl_Text_Editor* ed) {
    EditorWindow* win = (EditorWindow*)ed->user_data();
    if (win) {
        redo_edit(ed, win);
    }
    return 1; // Return 1 to indicate the key event was handled
}


void zoom_in(void* data) {
    EditorWindow* window = static_cast<EditorWindow*>(data);
    if (!window || !window->editor) return;

    int current_fontsize = window->editor->textsize();
    if (current_fontsize < MAX_FONT_SIZE) {
        window->editor->textsize(current_fontsize + 2);
        window->editor->resize(window->editor->x(), window->editor->y(),
        window->editor->w(), window->editor->h()); // We need to resize everything to avoid an issue with FLTK where the line spacing doesn't get recomputed automatically 
        window->editor->redraw();                   // Force widget to redraw with new font size
    }
}


void zoom_out(void* data) {
    EditorWindow* window = static_cast<EditorWindow*>(data);
    if (!window || !window->editor) return;

    int current_fontsize = window->editor->textsize();
    if (current_fontsize > MIN_FONT_SIZE) { 
        window->editor->textsize(current_fontsize - 2);
        window->editor->resize(window->editor->x(), window->editor->y(),
                                window->editor->w(), window->editor->h());
        window->editor->redraw();                   
    }
}


void cut_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !win->editor) return;
    Fl_Text_Editor::kf_cut(0, win->editor);
}

void copy_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !win->editor) return;
    Fl_Text_Editor::kf_copy(0, win->editor);
}

void paste_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !win->editor) return;
    Fl_Text_Editor::kf_paste(0, win->editor);
}

void delete_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;
    textbuf->remove_selection();
}

void select_all_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;
    textbuf->select(0, textbuf->length());
}


//void encrypt_text(Fl_Widget* w, void* data) {} 
//void decrypt_text(Fl_Widget* w, void* data) {}



/* --- Stuff for find and replace dialogue --- */


// show find and replace window
void show_findandreplace(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;

    edited_since_find = false;
    update_count(data);
    win->replace_dlg->show();
    return;
}


// find and select previous occurrence of a word
void find_previous_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;

    const char* find = win->find_text->value();
    if (strcmp(find, "") == 0) {
        fl_alert("Find box is empty.");
        return;
    }
    int pos = win->editor->insert_position();
    
    // If a word is currently selected the cursor will automatically be at the end of the selected word, whereas we want to start the search at the start. (This is necessary to avoid re-finding the same match). To fix this, we do:
    bool has_selection = textbuf->selection_position(&sel_start, &sel_end);
    if (has_selection) 
        pos = sel_start;

    // Also: search_backward can return a match starting at or overlapping `pos` itself, so searching from the raw insert_position can re-find the match we're already next to instead of an earlier one.
    // To fix this, we step back by 1 first so the search starts strictly before the current position/selection.
    pos -= 1;

    // reset to 0 if any of these actions caused the cursor to jump before 0  
    if (pos < 0) pos = 0;
    
    edited_since_find = false;

    // finds the previous match from the current cursor position 
    int found = textbuf->search_backward(pos, find, &pos);
    if (found) {
        // Found a match; select and update the position...
        textbuf->select(pos, pos+strlen(find));
        win->editor->insert_position(pos+strlen(find));
        win->editor->show_insert_position();
        // we also update sel_start and sel_end for tracking current selection position (see index_of_selection())
        bool has_selection = textbuf->selection_position(&sel_start, &sel_end);

    } // if no match found later on, try looping round and searching from the end 
    else {
        found = textbuf->search_backward(strlen(textbuf->text()), find, &pos);
        if (found) {
            textbuf->select(pos, pos+strlen(find));
            win->editor->insert_position(pos+strlen(find));
            win->editor->show_insert_position();
            bool has_selection = textbuf->selection_position(&sel_start, &sel_end);
        } 
        else {
            update_count(data);
            return;
        }
    }
    update_count(data);
    return;
}

// find and select next occurrence of a word 
void find_next_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;

    const char* find = win->find_text->value();
    if (strcmp(find, "") == 0) {
        fl_alert("Find box is empty.");
        return;
    }

    int pos = win->editor->insert_position();
    // similar as find_previous_cb but replace search direction 
    // finds the next match from the current cursor position 
    // we don't have to do all the funny position updates here; for search_forward WYSIWYG
    int found = textbuf->search_forward(pos, find, &pos);

    edited_since_find = false;

    if (found) {
        // Found a match; select and update the position...
        textbuf->select(pos, pos+strlen(find));
        win->editor->insert_position(pos+strlen(find));
        win->editor->show_insert_position();
        // track selection 
        bool has_selection = textbuf->selection_position(&sel_start, &sel_end);

    } // if no match found later on, try looping round and searching from the start 
    else {
        found = textbuf->search_forward(0, find, &pos);
        if (found) {
            textbuf->select(pos, pos+strlen(find));
            win->editor->insert_position(pos+strlen(find));
            win->editor->show_insert_position();
            bool has_selection = textbuf->selection_position(&sel_start, &sel_end);
        } 
        else {
            update_count(data);
            return;
        }
    }
    update_count(data);
    return;
}


// replace selected text with something 
void replace_selection_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;

    const char* replace = win->replace_with_text->value();

    bool has_selection = textbuf->selection_position(&sel_start, &sel_end);

    // if no selection, pass
    if (sel_start == sel_end) {
        fl_alert("Nothing is currently selected.");
        return;
    }

    if (has_selection) {
        textbuf->remove_selection();
        textbuf->insert(sel_start, replace);
        win->editor->insert_position(sel_start+strlen(replace));
        win->editor->show_insert_position();
    }
    else return;
}

// replace all matches with "find" with another word
void replace_all_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;

    const char* find = win->find_text->value();
    if (strcmp(find, "") == 0) {
        fl_alert("Find box is empty.");
        return;
    }
    const char* replace = win->replace_with_text->value();

    int replace_count = 0;
    win->editor->insert_position(0);
    
    for (;;) {
        int pos = win->editor->insert_position();
        int found = textbuf->search_forward(pos, find, &pos);
        // leave loop if nothing found
        if (!found) break;

        textbuf->select(pos, pos + strlen(find));
        textbuf->remove_selection();
        textbuf->insert(pos, replace);
        win->editor->insert_position(pos + strlen(replace));
        replace_count++;
    }

    if (replace_count > 0) fl_message("Replaced %d occurrence(s) of '%s' with '%s'.", replace_count, find, replace);

    else fl_message("The string '%s' does not appear in this file.", find);
    
}

// We want to print the index of a searched word e.g. 2 of 3 if we are currently selecting "the quick brown fox jumped over the <quick> quick dog" -- can easily reuse code from the above to do this. 

// count how many times the word in the "find" box appears total 
// if the box is empty, returns 0. if error, returns -1 (though this should hopefully never happen)
int count_total_occurrences(void* data) {
    EditorWindow* win = get_window(nullptr, data);
    if (!win || !textbuf) return -1;

    const char* find = win->find_text->value();
    if (strcmp(find, "") == 0) return 0;
        
    int count = 0;
    // start at beginning 
    int pos = 0;

    for (;;) {
        int found = textbuf->search_forward(pos, find, &pos);
        // offset so we start after in the next search 
        pos += strlen(find);
        // leave loop once nothing found
        if (!found) break;

        // otherwise add 1 to count 
        count++;
    }
    return count;
}


// count index of currently selected occurrence of input of "find". 
// current selection is tracked using sel_start/sel_end which are only updated when we click to go back/forward 
// if "find" is empty, returns 0. if error, returns -1 (though this should hopefully never happen)
int index_of_selection(void* data) {
    EditorWindow* win = get_window(nullptr, data);
    if (!win || !textbuf) return -1;

    const char* find = win->find_text->value();
    if (strcmp(find, "") == 0) return 0;

    int count = 0;
    int pos = win->editor->insert_position();
    for (;;) {
        // we need to start the search from pos -1 for similar reasons as why we subtracted 1 in find_previous_cb()
        int found = textbuf->search_backward(pos - 1, find, &pos);
        // update so we start next search backtracking from before word 
        pos -= strlen(find) - 1;
        // leave loop once nothing found
        if (!found) break;

        // otherwise add 1 to count 
        count++;
    }

    return count;
}

// combine previous two into update handler for counter 
void update_count(void* data) {
    EditorWindow* win = get_window(nullptr, data);
    if (!win || !textbuf) return;

    std::string count_text;

    int total_occurrences = count_total_occurrences(win);

    if (edited_since_find) {
        count_text = "Editing...";
    } 
    else if (total_occurrences == 0) {
        count_text = "No Results";
    }
    else {
        int current_index = index_of_selection(win);

        count_text = std::to_string(current_index) + " of " + std::to_string(total_occurrences);
    }

    win->match_count_label->copy_label(count_text.c_str());
    win->match_count_label->redraw();
}


// cancel out of find+replace window 
void replace_cancel_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(nullptr, data);
    if (!win || !textbuf) return;

    win->replace_dlg->hide();
}

/* --- For toggling word wrapping and line numbering --- */
void toggle_wordwrap_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !win->editor) return;

    // figure out if toggle is on or not 
    const int wordwrap_status = win->menu->mvalue()->value();

    if (wordwrap_status) {
        win->editor->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
    } else {
        win->editor->wrap_mode(Fl_Text_Display::WRAP_NONE, 0);
    }
    win->editor->redraw();
}

void toggle_linenumbers_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !win->editor) return;

    // same as above function 
    const int linenumbers_status = win->menu->mvalue()->value();
    if (linenumbers_status) {
        win->editor->linenumber_width(45);
    } else {
        win->editor->linenumber_width(0);
    }
    win->editor->redraw();
}


/* --- Stuff for encrypt/decrypt --- */

void show_encrypt_window(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;

    std::strcpy(encrypt_mode, "Encrypt");
    win->encrypt_dlg->label(encrypt_mode);
    win->encrypt_dlg->show();
}
void show_decrypt_window(Fl_Widget* w, void* data) { 
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;

    std::strcpy(encrypt_mode, "Decrypt");
    win->encrypt_dlg->label(encrypt_mode);
    win->encrypt_dlg->show();
}
void cancel_encrypt_cb(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(nullptr, data);
    if (!win || !textbuf) return;

    win->encrypt_dlg->hide();
}

void cb_128(Fl_Widget* w, void* data) {
    keysize = 128;
}
void cb_192(Fl_Widget* w, void* data) {
    keysize = 192;
}
void cb_256(Fl_Widget* w, void* data) {
    keysize = 256;
}

void explain_encryption(Fl_Widget* w, void* data) {
    fl_message("%s text using Advanced Encryption Standard (AES-CBC), the only public type of cipher approved by the NSA for encryption of top secret information. \nThe key sizes may be understood as follows: \nAES-128: Fast and secure; ideal for everyday commercial and consumer applications.\nAES-192: Balanced security; suitable for strict corporate and regulatory compliance needs.\nAES-256: Maximum protection; essential for classified, financial, or long-term data. Currently considered resiliant even against future quantum computers.", encrypt_mode);
}

// add/remove whitespace when encrypting so that we don't get a massive single line causing lots of lag 
std::string add_whitespace(const std::string &s) {
    std::string wrapped;
    size_t width = 76;
    wrapped.reserve(s.size() + s.size() / width + 1);
    for (size_t i = 0; i < s.size(); i += width) {
        wrapped += s.substr(i, width);
        wrapped += '\n';
    }
    return wrapped;
}
std::string remove_whitespace(const std::string &s) {
    std::string clean;
    clean.reserve(s.size());
    for (char c : s) {
        if (c != '\n' && c != '\r') clean += c;
    }
    return clean;
}


void encrypt_decrypt_text(Fl_Widget* w, void* data) {
    EditorWindow* win = get_window(w, data);
    if (!win || !textbuf) return;

    const char* password = win->password_input->value();
    
    // raise a warning if no password typed
    if (strcmp(password, "") == 0) {
        fl_message("Please enter a password.");
        return;
    }

    // raise a warning if no keysize selected
    if (!keysize) {
        fl_message("Please select a key size.");
        return;
    }

    // raise a warning if the file is empty 
    if (strcmp(textbuf->text(), "") == 0) {
        fl_message("File currently contains no text. Please add content before performing encryption and decryption.");
        return;
    }

    std::string input_text = textbuf->text();

    if (strcmp(encrypt_mode, "Encrypt") == 0) {
        try {
            // convert password to packaged salt + key 
            std::string packaged = PBKDF2::pbkdf2_final(password, keysize);

            // split salt and key, convert key to hex 
            std::string salt = packaged.substr(0, 16);
            std::string raw_key_bytes = packaged.substr(16);
            std::vector<uint8_t> key_bytes(raw_key_bytes.begin(), raw_key_bytes.end());
            std::string key_hex = BytesHex::bytes_to_hex(key_bytes);

            // Encrypt text and package with salt
            std::string ciphertext_b64 = AES::encryptMsg(input_text, key_hex, keysize);
            // we must convert the salt to base 64 as well. reason: some of the byte values output by PBKDF2 will not be valid UTF-8. Note: this will make the salt 24 characters instead of 16. 
            std::vector<uint8_t> salt_bytes = std::vector<uint8_t>(salt.begin(), salt.end());
            std::string salt_b64 = B64::base64_encode(salt_bytes);

            std::string output = salt_b64 + ciphertext_b64;

            // update textbuf and hide dialogue 
            output = add_whitespace(output);
            textbuf->text(output.c_str());
            win->encrypt_dlg->hide();
        }
        catch (...) {
            fl_message("An unexpected error occurred.");
        }

    }
    else if (strcmp(encrypt_mode, "Decrypt") == 0) {
        // delete added whitespace
        input_text = remove_whitespace(input_text);
        // split salt and ciphertext; they are automatically concatenated  
        std::string salt_b64 = input_text.substr(0, 24);
        std::string ciphertext_b64 = input_text.substr(24);

        // convert salt from b64->bytes->string
        std::vector<uint8_t> salt_bytes = B64::base64_decode(salt_b64);
        std::string salt = std::string(salt_bytes.begin(), salt_bytes.end());
        // use salt to compute key from password, extract key from concatenation
        std::string packaged = PBKDF2::pbkdf2_final(password, salt, keysize);
        std::string key_raw = packaged.substr(16);

        std::vector<uint8_t> key_bytes(key_raw.begin(), key_raw.end());
        std::string key_hex = BytesHex::bytes_to_hex(key_bytes); 

        // decrypt text 
        std::string plaintext = AES::decryptMsg(ciphertext_b64, key_hex, keysize);

        // update textbuf and hide dialogue 
        textbuf->text(plaintext.c_str());
        win->encrypt_dlg->hide();
    }
    else {
        fl_message("An unexpected error occurred.");
    }
}