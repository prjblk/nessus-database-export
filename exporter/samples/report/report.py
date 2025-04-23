#!/usr/bin/env python3
import configparser
import pymysql.cursors
import os
import sys
import argparse
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Line, PolyLine
from reportlab.graphics.charts.linecharts import HorizontalLineChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.charts.textlabels import Label
from collections import defaultdict

def get_severity_info(severity):
    severity_map = {
        0: ("Informational", colors.lightblue),
        1: ("Low", colors.lightgreen),
        2: ("Medium", colors.yellow),
        3: ("High", colors.orange),
        4: ("Critical", colors.red)
    }
    return severity_map.get(int(severity), ("Unknown", colors.grey))

def get_scan_stats(scan_id, limit=5):
    # Read configuration
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), '../../config.ini'))

    # Get database connection details
    db_hostname = config.get('mysql', 'hostname')
    username = config.get('mysql', 'username')
    password = config.get('mysql', 'password')
    database = config.get('mysql', 'database')

    try:
        # Connect to the database
        connection = pymysql.connect(
            host=db_hostname,
            user=username,
            password=password,
            db=database,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )

        with connection.cursor() as cursor:
            # Get the most recent scan stats
            stats = []
            for offset in range(limit):
                cursor.callproc('get_scan_stats', (scan_id, offset))
                result = cursor.fetchone()
                if result:
                    stats.append(result)
                else:
                    break
            return stats

    except Exception as e:
        print(f"Error getting scan stats: {e}")
        return []
    finally:
        if 'connection' in locals():
            connection.close()

def get_scan_results(scan_id, offset=0, include_informational=False):
    # Read configuration
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), '../../config.ini'))

    # Get database connection details
    db_hostname = config.get('mysql', 'hostname')
    username = config.get('mysql', 'username')
    password = config.get('mysql', 'password')
    database = config.get('mysql', 'database')

    try:
        # Connect to the database
        connection = pymysql.connect(
            host=db_hostname,
            user=username,
            password=password,
            db=database,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )

        with connection.cursor() as cursor:
            # Get scan stats first
            scan_stats = get_scan_stats(scan_id)
            
            # Call the stored procedure for detailed results
            cursor.callproc('get_scan_results', (scan_id, offset))
            results = cursor.fetchall()
            
            if results:
                # Group results by host
                host_findings = defaultdict(list)
                for row in results:
                    # Skip informational findings if not included
                    if not include_informational and row['severity'] == 0:
                        continue
                    host_findings[(row['host_ip'], row['host_fqdn'])].append(row)

                # Generate PDF
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                pdf_filename = f'nessus_scan_{scan_id}_{timestamp}.pdf'
                pdf_path = os.path.join(os.path.dirname(__file__), pdf_filename)
                
                # Create the PDF document in landscape mode with reduced margins
                doc = SimpleDocTemplate(
                    pdf_path,
                    pagesize=landscape(A4),
                    rightMargin=36,
                    leftMargin=36,
                    topMargin=36,
                    bottomMargin=36
                )
                
                # Create styles
                styles = getSampleStyleSheet()
                title_style = ParagraphStyle(
                    'CustomTitle',
                    parent=styles['Heading1'],
                    fontSize=24,
                    spaceAfter=20
                )
                heading_style = ParagraphStyle(
                    'CustomHeading',
                    parent=styles['Heading2'],
                    fontSize=16,
                    spaceAfter=8
                )
                normal_style = styles['Normal']
                
                # Build the PDF content
                story = []
                
                # Add title
                story.append(Paragraph(f"Nessus Scan Report", title_style))
                story.append(Paragraph(f"Scan ID: {scan_id}", heading_style))
                story.append(Spacer(1, 10))

                # Add scan statistics graph if available
                if scan_stats:
                    story.append(Paragraph("Scan Statistics Over Time", heading_style))
                    story.append(Spacer(1, 5))
                    
                    # Sort scan stats by date (oldest to newest)
                    scan_stats.sort(key=lambda x: x['scan_start'])
                    
                    # Create the drawing
                    drawing = Drawing(doc.width, 260)
                    
                    # Create the line chart
                    chart = HorizontalLineChart()
                    chart.x = (doc.width - (doc.width - 150)) / 2  # Center the chart
                    chart.y = 50
                    chart.height = 200
                    chart.width = doc.width - 150
                    
                    # Prepare data for the chart
                    dates = [datetime.fromtimestamp(stat['scan_start']).strftime('%Y-%m-%d %H:%M') for stat in scan_stats]
                    critical_data = [stat['critical_count'] for stat in scan_stats]
                    high_data = [stat['high_count'] for stat in scan_stats]
                    medium_data = [stat['medium_count'] for stat in scan_stats]
                    low_data = [stat['low_count'] for stat in scan_stats]
                    
                    # Calculate max value and appropriate step size
                    max_value = max(max(critical_data), max(high_data), max(medium_data), max(low_data))
                    if max_value <= 5:
                        step = 1
                    elif max_value <= 10:
                        step = 2
                    elif max_value <= 20:
                        step = 5
                    else:
                        step = 10
                    
                    # Set up the chart data
                    chart.data = [critical_data, high_data, medium_data, low_data]
                    chart.categoryAxis.categoryNames = dates
                    chart.categoryAxis.labels.angle = 0
                    chart.categoryAxis.labels.fontSize = 8
                    chart.categoryAxis.labels.fontName = 'Helvetica'
                    
                    # Set up the value axis
                    chart.valueAxis.valueMin = 0
                    chart.valueAxis.valueMax = max_value + step
                    chart.valueAxis.valueStep = step
                    chart.valueAxis.labels.fontName = 'Helvetica'
                    
                    # Add axis labels
                    x_label = Label()
                    x_label.setText('Scan Date')
                    x_label.fontName = 'Helvetica'
                    x_label.fontSize = 15
                    x_label.x = chart.x + chart.width/2
                    x_label.y = chart.y - 40
                    drawing.add(x_label)
                    
                    y_label = Label()
                    y_label.setText('Number of Findings')
                    y_label.fontName = 'Helvetica'
                    y_label.fontSize = 13
                    y_label.x = chart.x - 40
                    y_label.y = chart.y + chart.height/2
                    y_label.angle = 90
                    drawing.add(y_label)
                    
                    # Set up the lines
                    chart.lines[0].strokeColor = colors.red
                    chart.lines[1].strokeColor = colors.orange
                    chart.lines[2].strokeColor = colors.yellow
                    chart.lines[3].strokeColor = colors.lightgreen
                    
                    # Set default stroke width for all lines
                    chart.lines.strokeWidth = 2
                    
                    # Add the chart to the drawing
                    drawing.add(chart)
                    
                    # Add a legend
                    legend = Legend()
                    legend.alignment = 'left'
                    legend.fontName = 'Helvetica'
                    legend.fontSize = 8
                    legend.x = chart.x
                    legend.y = chart.y - 60
                    legend.colorNamePairs = [
                        (colors.red, 'Critical'),
                        (colors.orange, 'High'),
                        (colors.yellow, 'Medium'),
                        (colors.lightgreen, 'Low')
                    ]
                    drawing.add(legend)
                    
                    # Add the drawing to the story
                    story.append(drawing)
                    story.append(Spacer(1, 40))
                    story.append(PageBreak())  # Add a page break after the chart
                
                # Add findings for each host
                for (host_ip, host_fqdn), findings in host_findings.items():
                    # Sort findings by severity (highest first)
                    findings.sort(key=lambda x: x['severity'] if x['severity'] is not None else 0, reverse=True)
                    
                    # Host information
                    story.append(Paragraph(f"Host: {host_ip} ({host_fqdn})", heading_style))
                    
                    # Create table header
                    table_data = [[Paragraph('Vulnerability Name', normal_style),
                                 Paragraph('Severity', normal_style),
                                 Paragraph('Description', normal_style),
                                 Paragraph('Solution', normal_style),
                                 Paragraph('Port', normal_style)]]
                    
                    # Add findings to table
                    for finding in findings:
                        # Convert all values to strings explicitly
                        name = str(finding['name']) if finding['name'] is not None else ''
                        severity_num = finding['severity'] if finding['severity'] is not None else 0
                        severity_text, severity_color = get_severity_info(severity_num)
                        description = str(finding['description']) if finding['description'] is not None else ''
                        solution = str(finding['solution']) if finding['solution'] is not None else ''
                        port = str(finding['port']) if finding['port'] is not None else ''
                        
                        table_data.append([
                            Paragraph(name, normal_style),
                            Paragraph(severity_text, normal_style),
                            Paragraph(description, normal_style),
                            Paragraph(solution, normal_style),
                            Paragraph(port, normal_style)
                        ])
                    
                    # Calculate available width (landscape A4 - margins)
                    available_width = doc.width
                    
                    # Create table with optimized column widths for landscape mode
                    table = Table(table_data, colWidths=[
                        available_width * 0.15,  # Vulnerability Name: 15%
                        available_width * 0.10,  # Severity: 10%
                        available_width * 0.35,  # Description: 35%
                        available_width * 0.25,  # Solution: 35%
                        available_width * 0.10   # Port: 10%
                    ])

                    # Create table style with severity-based background colors
                    table_style = [
                        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),  # Header row
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('LEFTPADDING', (0, 0), (-1, -1), 4),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('WORDWRAP', (0, 0), (-1, -1), True),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP')
                    ]

                    # Add severity-based background colors for each row
                    for i, finding in enumerate(findings, start=1):
                        severity_num = finding['severity'] if finding['severity'] is not None else 0
                        _, severity_color = get_severity_info(severity_num)
                        table_style.append(('BACKGROUND', (1, i), (1, i), severity_color))

                    table.setStyle(TableStyle(table_style))
                    
                    story.append(table)
                    story.append(Spacer(1, 10))
                
                # Build the PDF
                doc.build(story)
                print(f"PDF report generated: {pdf_filename}")
            else:
                print(f"No results found for Scan ID {scan_id}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    finally:
        if 'connection' in locals():
            connection.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate Nessus scan report')
    parser.add_argument('scan_id', type=int, help='Scan ID to generate report for')
    parser.add_argument('--offset', type=int, default=0, help='Offset for pagination')
    parser.add_argument('--include-informational', action='store_true', help='Include informational findings in the report')
    
    args = parser.parse_args()
    
    get_scan_results(args.scan_id, args.offset, args.include_informational)
