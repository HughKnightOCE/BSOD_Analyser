#!/usr/bin/env python3
"""
Logo generator for BSOD Analyzer
Creates app.ico (taskbar) and logo.png (GUI logo) with grey/white/black design + purple accents
"""

import sys
from pathlib import Path

def generate_with_pil():
    """Generate logo using PIL if available"""
    try:
        from PIL import Image, ImageDraw, ImageFont
        
        # Create large image for GUI logo (512x512)
        gui_img = Image.new('RGBA', (512, 512), color=(255, 255, 255, 0))
        draw = ImageDraw.Draw(gui_img)
        
        # Try to load a nice font
        try:
            font_title = ImageFont.truetype("C:\\Windows\\Fonts\\segoeui.ttf", 48)
            font_subtitle = ImageFont.truetype("C:\\Windows\\Fonts\\segoeui.ttf", 18)
        except:
            font_title = ImageFont.load_default()
            font_subtitle = ImageFont.load_default()
        
        # Dark grey background with subtle gradient
        for y in range(512):
            intensity = int(42 + (y / 512) * 15)  # Subtle gradient
            draw.rectangle([(0, y), (512, y+1)], fill=(intensity, intensity, intensity))
        
        # Draw a subtle purple accent bar on the left
        draw.rectangle([(0, 0), (8, 512)], fill=(124, 58, 237))
        
        # Draw "BSOD Analyzer" as main text (professional styling)
        text_bbox = draw.textbbox((0, 0), "BSOD Analyzer", font=font_title)
        text_width = text_bbox[2] - text_bbox[0]
        text_height = text_bbox[3] - text_bbox[1]
        text_x = 256 - text_width // 2
        text_y = 200 - text_height // 2
        draw.text((text_x, text_y), "BSOD Analyzer", font=font_title, fill=(240, 240, 240))
        
        # Draw separator line in purple
        draw.rectangle([(100, 270), (412, 272)], fill=(124, 58, 237))
        
        # Draw "Windows Diagnostic Tool" subtitle
        text_bbox = draw.textbbox((0, 0), "Windows Diagnostic Tool", font=font_subtitle)
        text_width = text_bbox[2] - text_bbox[0]
        text_x = 256 - text_width // 2
        draw.text((text_x, 310), "Windows Diagnostic Tool", font=font_subtitle, fill=(180, 180, 180))
        
        # Draw version indicator
        text_bbox = draw.textbbox((0, 0), "v0.9.2", font=font_subtitle)
        text_width = text_bbox[2] - text_bbox[0]
        text_x = 256 - text_width // 2
        draw.text((text_x, 410), "v0.9.2", font=font_subtitle, fill=(124, 58, 237))
        
        # Save as PNG for GUI
        gui_img.save(Path(__file__).parent / "logo.png")
        print("[PASS] GUI logo created: logo.png (512x512)")
        
        # Create ICO for taskbar (professional badge style)
        ico_sizes = [(32, 32), (64, 64), (128, 128)]
        ico_images = []
        
        for size in ico_sizes:
            ico_img = Image.new('RGBA', size, color=(255, 255, 255, 0))
            draw_ico = ImageDraw.Draw(ico_img)
            
            # Dark grey background
            draw_ico.rectangle([(0, 0), (size[0], size[1])], fill=(42, 42, 45))
            
            # Purple accent bar on left
            bar_width = max(1, size[0] // 10)
            draw_ico.rectangle([(0, 0), (bar_width, size[1])], fill=(124, 58, 237))
            
            # White square (badge background)
            padding = max(1, size[0] // 8)
            draw_ico.rectangle(
                [(padding, padding), (size[0] - padding, size[1] - padding)],
                fill=(240, 240, 240),
                outline=(180, 180, 180),
                width=1
            )
            
            ico_images.append(ico_img)
        
        # Save as ICO (Windows icon format)
        ico_images[0].save(
            Path(__file__).parent / "app.ico",
            format="ICO",
            sizes=[(32, 32), (64, 64), (128, 128)]
        )
        print("[PASS] Taskbar icon created: app.ico (32x32, 64x64, 128x128)")
        
        return True
        
    except ImportError:
        print("[NOTE] PIL (Pillow) not installed. Install with: pip install Pillow")
        return False


def generate_with_svg():
    """Generate logo as SVG if PIL is not available"""
    
    # GUI Logo SVG
    gui_svg = '''<?xml version="1.0" encoding="UTF-8"?>
<svg width="512" height="512" xmlns="http://www.w3.org/2000/svg">
    <!-- Dark grey gradient background -->
    <defs>
        <linearGradient id="bgGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" style="stop-color:#2a2a2d;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#1a1a1d;stop-opacity:1" />
        </linearGradient>
    </defs>
    
    <!-- Background -->
    <rect width="512" height="512" fill="url(#bgGrad)"/>
    
    <!-- White circle (center) -->
    <circle cx="256" cy="256" r="176" fill="#f0f0f0" stroke="#c8c8c8" stroke-width="2"/>
    
    <!-- Purple accent circle (top right) -->
    <circle cx="420" cy="85" r="55" fill="#7c3aed" opacity="0.8" stroke="#7c3aed" stroke-width="2"/>
    
    <!-- "BA" Text -->
    <text x="256" y="310" font-family="Segoe UI, Arial, sans-serif" font-size="140" font-weight="bold" 
          text-anchor="middle" fill="#2a2a2d">BA</text>
    
    <!-- Purple underline -->
    <rect x="150" y="340" width="212" height="10" fill="#7c3aed" rx="5"/>
    
    <!-- "ANALYZER" text -->
    <text x="256" y="410" font-family="Segoe UI, Arial, sans-serif" font-size="38" font-weight="normal"
          text-anchor="middle" fill="#c8c8c8">ANALYZER</text>
</svg>'''
    
    # Icon SVG (smaller version)
    icon_svg = '''<?xml version="1.0" encoding="UTF-8"?>
<svg width="256" height="256" xmlns="http://www.w3.org/2000/svg">
    <defs>
        <linearGradient id="bgGrad" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" style="stop-color:#2a2a2d;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#1a1a1d;stop-opacity:1" />
        </linearGradient>
    </defs>
    
    <rect width="256" height="256" fill="url(#bgGrad)"/>
    <circle cx="128" cy="128" r="88" fill="#f0f0f0" stroke="#c8c8c8" stroke-width="1"/>
    <circle cx="210" cy="43" r="28" fill="#7c3aed" opacity="0.8" stroke="#7c3aed" stroke-width="1"/>
    <text x="128" y="155" font-family="Segoe UI, Arial, sans-serif" font-size="70" font-weight="bold"
          text-anchor="middle" fill="#2a2a2d">BA</text>
    <rect x="75" y="170" width="106" height="5" fill="#7c3aed" rx="2.5"/>
    <text x="128" y="210" font-family="Segoe UI, Arial, sans-serif" font-size="18" font-weight="normal"
          text-anchor="middle" fill="#c8c8c8">ANALYZER</text>
</svg>'''
    
    # Save SVG files (these won't work directly as app.ico but are useful reference)
    Path(__file__).parent / "logo.svg"
    with open(Path(__file__).parent / "logo.svg", "w") as f:
        f.write(gui_svg)
    print("[PASS] GUI logo SVG created: logo.svg")
    
    with open(Path(__file__).parent / "logo_icon.svg", "w") as f:
        f.write(icon_svg)
    print("[PASS] Icon SVG created: logo_icon.svg")
    
    print("\n[NOTE] SVG files created, but Windows requires .ico and .png files.")
    print("       Please convert these SVG files to PNG/ICO using an online converter:")
    print("       - https://cloudconvert.com (SVG to PNG/ICO)")
    print("       - Place logo.png in the project folder")
    print("       - Place app.ico in the project folder")
    
    return True


if __name__ == "__main__":
    print("=" * 80)
    print("BSOD Analyzer Logo Generator")
    print("=" * 80)
    
    if not generate_with_pil():
        print("\n[INFO] Generating SVG versions instead...")
        generate_with_svg()
    
    print("\n" + "=" * 80)
    print("Logo generation complete!")
    print("=" * 80)
