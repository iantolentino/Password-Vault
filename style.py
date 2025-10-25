"""
Styling and theme configuration for the Password Vault application
"""
import tkinter as tk
from tkinter import ttk

# Modern dark theme colors
DARK_THEME = {
    "primary_bg": "#1a1a1a",
    "secondary_bg": "#2d2d2d",
    "tertiary_bg": "#3d3d3d",
    "primary_fg": "#ffffff",
    "secondary_fg": "#cccccc",
    "accent": "#4a90e2",
    "accent_hover": "#357abd",
    "success": "#28a745",
    "warning": "#ffc107",
    "danger": "#dc3545",
    "border": "#404040",
    "card_bg": "#252525"
}

def configure_styles(root):
    """Configure ttk styles for modern dark theme"""
    style = ttk.Style(root)
    
    # Try to use modern theme if available
    try:
        style.theme_use('clam')
    except:
        pass
    
    # Configure styles
    style.configure('Main.TFrame', background=DARK_THEME['primary_bg'])
    style.configure('Card.TFrame', background=DARK_THEME['card_bg'])
    style.configure('Border.TFrame', background=DARK_THEME['border'])
    
    # Labels
    style.configure('Title.TLabel', 
                   background=DARK_THEME['primary_bg'],
                   foreground=DARK_THEME['primary_fg'],
                   font=('Segoe UI', 16, 'bold'))
    
    style.configure('Subtitle.TLabel',
                   background=DARK_THEME['card_bg'],
                   foreground=DARK_THEME['secondary_fg'],
                   font=('Segoe UI', 10))
    
    style.configure('Normal.TLabel',
                   background=DARK_THEME['card_bg'],
                   foreground=DARK_THEME['primary_fg'],
                   font=('Segoe UI', 10))
    
    # Buttons
    style.configure('Primary.TButton',
                   background=DARK_THEME['accent'],
                   foreground=DARK_THEME['primary_fg'],
                   borderwidth=0,
                   focuscolor='none',
                   font=('Segoe UI', 10, 'bold'),
                   padding=(20, 10))
    
    style.configure('Secondary.TButton',
                   background=DARK_THEME['tertiary_bg'],
                   foreground=DARK_THEME['primary_fg'],
                   borderwidth=0,
                   focuscolor='none',
                   font=('Segoe UI', 10),
                   padding=(20, 10))
    
    style.configure('Danger.TButton',
                   background=DARK_THEME['danger'],
                   foreground=DARK_THEME['primary_fg'],
                   borderwidth=0,
                   focuscolor='none',
                   font=('Segoe UI', 10),
                   padding=(20, 10))
    
    # Entry fields
    style.configure('Modern.TEntry',
                   fieldbackground=DARK_THEME['tertiary_bg'],
                   foreground=DARK_THEME['primary_fg'],
                   borderwidth=1,
                   relief='flat',
                   padding=(10, 8))
    
    # Scrollbar
    style.configure('Modern.Vertical.TScrollbar',
                   background=DARK_THEME['tertiary_bg'],
                   darkcolor=DARK_THEME['tertiary_bg'],
                   lightcolor=DARK_THEME['tertiary_bg'],
                   troughcolor=DARK_THEME['secondary_bg'],
                   bordercolor=DARK_THEME['secondary_bg'],
                   arrowcolor=DARK_THEME['primary_fg'])
    
    return style

def apply_dark_theme(window):
    """Apply dark theme to a window"""
    window.configure(bg=DARK_THEME['primary_bg'])
    
    # Create a modern border effect
    border_frame = ttk.Frame(window, style='Border.TFrame')
    return border_frame

def create_modern_button(parent, text, command, style='Primary.TButton'):
    """Create a modern-looking button"""
    btn = ttk.Button(parent, text=text, command=command, style=style)
    return btn

def create_card_frame(parent, padding=20):
    """Create a modern card-style frame"""
    card = ttk.Frame(parent, style='Card.TFrame', padding=padding)
    return card