// Copyright (c) jfyo2 2026. Licensed under the MIT Licence.
// See the LICENCE file for full licence text.

#include <FL/Fl.H>
#include <FL/Fl_Text_Editor.H>
#include <FL/Fl_Menu_.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Input_.H>
#include <FL/Fl_Box.H>
#include <FL/fl_draw.H>
#include <FL/fl_ask.H>

// Custom flat box type for menu popups
void draw_truly_flat_box(int x, int y, int w, int h, Fl_Color c) {
    fl_color(c);
    fl_rectf(x, y, w, h);
}
Fl_Boxtype FL_TRULY_FLAT_BOX = (Fl_Boxtype)(FL_FREE_BOXTYPE);

void register_flat_menu_box() {
    Fl::set_boxtype(FL_TRULY_FLAT_BOX, draw_truly_flat_box, 0, 0, 0, 0);
}

// --- Nord palette, as packed 0xRRGGBB00 values for Fl::set_color / Fl_Color casts ---
#define NORD0  0x2E344000  // darkest background
#define NORD1  0x3B425200  // panel/dialog background
#define NORD2  0x434C5E00  // input fields, slightly raised
#define NORD3  0x4C566A00  // muted borders / inactive text
#define NORD4  0xD8DEE900  // main text
#define NORD6  0xECEFF400  // brightest text (labels, headings)
#define NORD8  0x88C0D000  // primary accent (cyan) -- cursor, selection, menu highlight
#define NORD9  0x81A1C100  // secondary blue -- unused by default, available for links/info
#define NORD10 0x5E81AC00  // dark blue -- unused by default, available for headers
#define NORD11 0xBF616A00  // red -- errors / warnings
#define NORD12 0xD0876800  // orange -- secondary/warm accent, e.g. modified-file indicator

// Applies a flat, dark, Nord-based theme to the whole application.
void apply_nord_theme() {
    register_flat_menu_box();

    Fl::scheme(nullptr);

    // Flatten every remaining box style so nothing renders a bevel/shadow
    Fl::set_boxtype(FL_UP_BOX, FL_FLAT_BOX);
    Fl::set_boxtype(FL_DOWN_BOX, FL_FLAT_BOX);
    Fl::set_boxtype(FL_UP_FRAME, FL_FLAT_BOX);
    Fl::set_boxtype(FL_DOWN_FRAME, FL_FLAT_BOX);
    Fl::set_boxtype(FL_THIN_UP_BOX, FL_FLAT_BOX);
    Fl::set_boxtype(FL_THIN_DOWN_BOX, FL_FLAT_BOX);
    Fl::set_boxtype(FL_ROUND_UP_BOX, FL_FLAT_BOX);
    Fl::set_boxtype(FL_ROUND_DOWN_BOX, FL_FLAT_BOX);
    Fl::set_boxtype(FL_ENGRAVED_BOX, FL_FLAT_BOX); // menu bar itself often uses this
    Fl::set_boxtype(FL_EMBOSSED_BOX, FL_FLAT_BOX);
    Fl::set_boxtype(FL_ROUND_UP_BOX, FL_FLAT_BOX); // already have this
    Fl::set_boxtype(FL_RSHADOW_BOX, FL_FLAT_BOX);  // Fl_Return_Button-family boxes sometimes default here
    Fl::set_boxtype(FL_RFLAT_BOX, FL_FLAT_BOX);

    // Global background/foreground -- affects windows, dialogs, plain boxes
    Fl::background(0x2E, 0x34, 0x40);      // nord0
    Fl::foreground(0xD8, 0xDE, 0xE9);      // nord4


    Fl::set_color(FL_FOREGROUND_COLOR, NORD4);
    Fl::set_color(FL_BACKGROUND_COLOR, NORD1);
    Fl::set_color(FL_BACKGROUND2_COLOR, NORD2); // used by input/text widget backgrounds specifically

    Fl::set_color(FL_SELECTION_COLOR, NORD8);

    Fl::set_color(FL_BLACK, NORD4); // default text color many widgets fall back to

    fl_message_font(FL_HELVETICA, 14); // modern sans rather than FLTK's old default
}

void style_editor(Fl_Text_Editor* editor) {
    editor->color(NORD0);          
    editor->textcolor(NORD4);         
    editor->cursor_color(NORD12);       
    editor->selection_color(NORD8);  
    editor->textfont(FL_COURIER);
    editor->textsize(14);

    editor->linenumber_bgcolor(NORD1);
    editor->linenumber_fgcolor(NORD8); 
    editor->linenumber_font(FL_COURIER);
    editor->linenumber_size(12);

    editor->scrollbar_width(14); // slightly slimmer than FLTK's chunky default

    editor->redraw();
}

// Applies flat/dark styling to a menu bar
void style_menu(Fl_Menu_* menu) {
    menu->color(NORD1);                // menu bar background
    menu->textcolor(NORD9);            // menu item text
    menu->selection_color(NORD8);      // hovered/selected items use the accent color
    menu->textfont(FL_HELVETICA);
    menu->textsize(15);

    menu->box(FL_TRULY_FLAT_BOX);

    menu->redraw();
}

void style_button(Fl_Button* btn) {
    btn->box(FL_FLAT_BOX);
    btn->down_box(FL_FLAT_BOX); 
    btn->color(NORD2);
    btn->labelcolor(NORD4);
    btn->selection_color(NORD8);
    btn->redraw();
}

void style_input(Fl_Input_* input) {
    input->box(FL_FLAT_BOX);
    input->color(NORD2);
    input->textcolor(NORD4);
    input->cursor_color(NORD12);
    input->selection_color(NORD8);
    input->redraw();
}

void style_box(Fl_Box* box) {
    box->box(FL_FLAT_BOX);
    box->color(NORD1);
    box->labelcolor(NORD4);
    box->redraw();
}

void style_dialog_window(Fl_Window* dlg) {
    dlg->color(NORD1);
}

void style_message_boxes() {
    fl_message_font(FL_HELVETICA, 14);
}