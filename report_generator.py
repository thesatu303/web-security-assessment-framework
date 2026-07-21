# report_generator.py
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib import colors
from datetime import datetime
import logging
import html

class ReportGenerator:
    def __init__(self, findings, start_time):
        self.findings = findings
        self.start_time = start_time
        self.logger = logging.getLogger(__name__)
    
    def escape_text(self, text):
        """Escape special characters for XML/HTML"""
        if isinstance(text, str):
            return html.escape(text)
        return str(text)
    
    def create_pdf_report(self, output_file):
        """Generate professional PDF report"""
        try:
            doc = SimpleDocTemplate(output_file, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1155CC'),
                spaceAfter=30
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#2E75B6'),
                spaceAfter=12
            )
            
            content_style = styles['Normal']
            
            # Title
            story.append(Paragraph("Security Assessment Report", title_style))
            story.append(Spacer(1, 12))
            
            # Summary
            story.append(Paragraph("Executive Summary", heading_style))
            summary_text = f"Assessment completed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            story.append(Paragraph(summary_text, content_style))
            story.append(Spacer(1, 12))
            
            # Total vulnerabilities
            total_vulns = sum(len(v) for v in self.findings.values() if isinstance(v, list))
            story.append(Paragraph(f"<b>Total Vulnerabilities Found: {total_vulns}</b>", content_style))
            story.append(Spacer(1, 20))
            
            # ====== RECONNAISSANCE SECTION (YEH ADD KIYA) ======
            # YEH SECTION PEHLE LIKHTE HO FINDINGS LOOP SE PEHLE
            if 'reconnaissance' in self.findings:
                recon = self.findings['reconnaissance']
                
                if isinstance(recon, dict) and recon:
                    story.append(Paragraph("<b>Reconnaissance Results</b>", heading_style))
                    
                    # Status Code
                    if recon.get('status_code'):
                        story.append(Paragraph(f"Status Code: {recon.get('status_code')}", content_style))
                    
                    # Page Title
                    if recon.get('page_title') and recon.get('page_title') != 'N/A':
                        page_title = self.escape_text(recon.get('page_title'))
                        story.append(Paragraph(f"Page Title: {page_title}", content_style))
                    
                    # URLs Found
                    urls = recon.get('urls_found', [])
                    if urls:
                        story.append(Paragraph(f"<b>URLs Found: {len(urls)}</b>", content_style))
                        
                        # Show first 15 URLs
                        for i, url in enumerate(urls[:15], 1):
                            escaped_url = self.escape_text(url)
                            story.append(Paragraph(f"{i}. {escaped_url}", content_style))
                        
                        # If more than 15, show count
                        if len(urls) > 15:
                            remaining = len(urls) - 15
                            story.append(Paragraph(f"... and {remaining} more URLs", content_style))
                    
                    # Parameters Found
                    params = recon.get('parameters', [])
                    if params:
                        story.append(Spacer(1, 10))
                        story.append(Paragraph(f"<b>Forms Found: {len(params)}</b>", content_style))
                        
                        for i, param in enumerate(params[:5], 1):
                            form_action = self.escape_text(param.get('form_action', 'N/A'))
                            form_method = param.get('form_method', 'POST')
                            fields_count = len(param.get('fields', []))
                            
                            story.append(Paragraph(
                                f"{i}. Action: {form_action} | Method: {form_method} | Fields: {fields_count}",
                                content_style
                            ))
                    
                    # Technologies Found
                    tech = recon.get('technologies', [])
                    if tech:
                        story.append(Spacer(1, 10))
                        tech_str = ', '.join(tech)
                        story.append(Paragraph(f"<b>Technologies Detected:</b> {tech_str}", content_style))
                    
                    story.append(Spacer(1, 20))
            
            # ====== END RECONNAISSANCE SECTION ======
            
            # ====== VULNERABILITIES SECTION (EXISTING CODE) ======
            # Findings by category
            for category, findings in self.findings.items():
                # Skip reconnaissance (already added above)
                if category == 'reconnaissance':
                    continue
                
                if isinstance(findings, list) and findings:
                    # Category heading
                    category_name = category.replace('_', ' ').title()
                    story.append(Paragraph(f"<b>{category_name}</b>", heading_style))
                    
                    # Count
                    count = len(findings)
                    story.append(Paragraph(f"Vulnerabilities Found: {count}", content_style))
                    story.append(Spacer(1, 8))
                    
                    # Details (escaped)
                    for i, finding in enumerate(findings, 1):
                        try:
                            vuln_type = self.escape_text(finding.get('type', 'Unknown'))
                            category_name = self.escape_text(finding.get('category', 'Unknown'))
                            payload = self.escape_text(finding.get('payload', 'N/A')[:100])
                            
                            detail_text = f"{i}. <b>{vuln_type}</b> - {category_name}"
                            story.append(Paragraph(detail_text, content_style))
                            story.append(Paragraph(f"Payload: {payload}", content_style))
                            story.append(Spacer(1, 6))
                        except:
                            story.append(Paragraph(f"{i}. Vulnerability Found", content_style))
                    
                    story.append(Spacer(1, 20))
            
            # ====== RECOMMENDATIONS SECTION ======
            story.append(Paragraph("Recommendations", heading_style))
            story.append(Paragraph("1. Address all identified vulnerabilities in order of severity", content_style))
            story.append(Paragraph("2. Implement input validation and output encoding", content_style))
            story.append(Paragraph("3. Use parameterized queries to prevent SQL injection", content_style))
            story.append(Paragraph("4. Implement Content Security Policy (CSP) headers", content_style))
            story.append(Paragraph("5. Implement CSRF tokens on all state-changing requests", content_style))
            story.append(Paragraph("6. Enforce strong authentication mechanisms", content_style))
            story.append(Paragraph("7. Conduct regular security audits and penetration testing", content_style))
            story.append(Spacer(1, 20))
            
            # ====== FOOTER ======
            footer_text = f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            story.append(Paragraph(footer_text, content_style))
            
            # Build PDF
            doc.build(story)
            self.logger.info(f"Report generated successfully: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            raise