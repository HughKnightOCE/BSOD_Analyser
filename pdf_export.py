"""
pdf_export.py
PDF report generation for BSOD Analyzer
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, List

class PDFReportGenerator:
    """Generate professional PDF reports from analysis data"""
    
    def __init__(self, output_path: Path = None):
        self.output_path = output_path or Path.cwd()
    
    def generate_report(self, analysis: Dict, filename: str = "BSOD_Report.pdf", format: str = 'pdf') -> Path:
        """Generate a comprehensive PDF or HTML report
        
        Args:
            analysis: Dictionary containing analysis results
            filename: Output filename (auto-adjusts extension based on format)
            format: 'pdf' or 'html' (defaults to 'pdf')
        
        Returns:
            Path to generated report
        """
        # Auto-adjust filename extension based on format
        if format.lower() == 'html' and not filename.endswith('.html'):
            filename = filename.replace('.pdf', '.html')
        elif format.lower() != 'html' and not filename.endswith('.pdf'):
            filename = filename + '.pdf'
        
        if format.lower() == 'html':
            return self._generate_html_fallback(analysis, filename)
        
        # Note: Requires reportlab library for PDF
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        except ImportError:
            return self._generate_html_fallback(analysis, filename)
        
        report_path = self.output_path / filename
        doc = SimpleDocTemplate(str(report_path), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1e40af'),
            spaceAfter=30,
            alignment=TA_CENTER,
        )
        story.append(Paragraph("BSOD Analyzer Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Report metadata
        metadata = [
            ['Report Generated:', datetime.now().strftime("%a, %d %b %Y %I:%M:%S %p")],
            ['Analysis Period:', f"{analysis.get('settings', {}).get('lookback_days', 30)} days"],
            ['Admin Rights:', str(analysis.get('admin', False))],
            ['Report Location:', str(analysis.get('report_path', 'N/A'))],
        ]
        table = Table(metadata, colWidths=[2*inch, 4*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e0e7ff')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ]))
        story.append(table)
        story.append(Spacer(1, 0.3*inch))
        
        # Summary section
        story.append(Paragraph("Summary", styles['Heading2']))
        bugchecks = analysis.get('bugchecks', [])
        summary_text = f"""
        <b>BugChecks Found:</b> {len(bugchecks)}<br/>
        <b>Suspects (Correlated Events):</b> {len(analysis.get('suspects', []))}<br/>
        <b>Recent Errors/Warnings:</b> {len(analysis.get('errors_recent', []))}<br/>
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        # BugChecks section
        if bugchecks:
            story.append(PageBreak())
            story.append(Paragraph("Blue Screen Events (BugChecks)", styles['Heading2']))
            
            bugcheck_data = [['Time', 'Stop Code', 'Name', 'Description']]
            for bc in bugchecks[:10]:
                bugcheck_data.append([
                    bc.get('TimeLocal', '')[:19],
                    bc.get('Code', ''),
                    bc.get('Name', ''),
                    bc.get('Desc', '')[:50] + '...' if len(bc.get('Desc', '')) > 50 else bc.get('Desc', '')
                ])
            
            table = Table(bugcheck_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 1.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))
            story.append(table)
        
        # Suspects section
        suspects = analysis.get('suspects', [])
        if suspects:
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("Suspicious Events (Near BSOD Times)", styles['Heading2']))
            
            suspect_data = [['Provider', 'Event ID', 'Count', 'Meaning']]
            for prov, eid, cnt in suspects[:10]:
                suspect_data.append([prov, str(eid), str(cnt), ''])
            
            table = Table(suspect_data, colWidths=[1.5*inch, 1*inch, 0.8*inch, 1.7*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#fee2e2')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(table)
        
        # Footer
        story.append(Spacer(1, 0.3*inch))
        footer_text = "This report was automatically generated by BSOD Analyzer. <b>Always back up critical data before running system repairs.</b>"
        story.append(Paragraph(footer_text, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        return report_path
    
    def _generate_html_fallback(self, analysis: Dict, filename: str) -> Path:
        """Generate HTML report as fallback when reportlab unavailable"""
        html_filename = filename.replace('.pdf', '.html')
        html_path = self.output_path / html_filename
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>BSOD Analyzer Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                h1 {{ color: #1e40af; border-bottom: 3px solid #1e40af; padding-bottom: 10px; }}
                h2 {{ color: #dc2626; margin-top: 30px; }}
                table {{ border-collapse: collapse; width: 100%; background: white; margin: 20px 0; }}
                th {{ background: #1e40af; color: white; padding: 10px; text-align: left; }}
                td {{ border: 1px solid #ddd; padding: 10px; }}
                tr:nth-child(even) {{ background: #f9f9f9; }}
                .metadata {{ background: #e0e7ff; padding: 15px; border-radius: 5px; }}
                .warning {{ color: #dc2626; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>BSOD Analyzer Report</h1>
            <div class="metadata">
                <p><b>Generated:</b> {datetime.now().strftime("%a, %d %b %Y %I:%M:%S %p")}</p>
                <p><b>Lookback Period:</b> {analysis.get('settings', {}).get('lookback_days', 30)} days</p>
                <p><b>Admin Rights:</b> {analysis.get('admin', False)}</p>
            </div>
            
            <h2>Summary</h2>
            <p><b>BugChecks Found:</b> {len(analysis.get('bugchecks', []))}</p>
            <p><b>Suspicious Events:</b> {len(analysis.get('suspects', []))}</p>
            <p><b>Recent Errors/Warnings:</b> {len(analysis.get('errors_recent', []))}</p>
            
            <h2>Blue Screen Events</h2>
            <table>
                <tr><th>Time</th><th>Stop Code</th><th>Name</th><th>Description</th></tr>
                {''.join([f"<tr><td>{bc.get('TimeLocal', '')[:19]}</td><td>{bc.get('Code', '')}</td><td>{bc.get('Name', '')}</td><td>{bc.get('Desc', '')[:100]}</td></tr>" 
                         for bc in analysis.get('bugchecks', [])[:10]])}
            </table>
            
            <h2>Suspected Problem Sources</h2>
            <table>
                <tr><th>Provider</th><th>Event ID</th><th>Occurrences</th></tr>
                {''.join([f"<tr><td>{s[0]}</td><td>{s[1]}</td><td>{s[2]}</td></tr>" for s in analysis.get('suspects', [])[:10]])}
            </table>
            
            <p class="warning">⚠️ Always back up critical data before running system repairs.</p>
        </body>
        </html>
        """
        
        html_path.write_text(html, encoding="utf-8")
        return html_path
