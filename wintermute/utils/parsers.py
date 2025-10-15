# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long
#
# MIT License
#
# Copyright (c) 2024,2025 Enrique Alfonso Sanchez Montellano (nahualito)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import datetime
import logging
from typing import List, Optional

import xlsxwriter
from bs4 import BeautifulSoup
from bs4.element import Tag

from ..core import Device, Service, Vulnerability

event_timestamp = (
    str(datetime.datetime.utcnow()).split(".")[0].replace(" ", "_").replace(":", "-")
)

log = logging.getLogger(__name__)


class BurpParser:
    """Class to parse the XML export for burp project

    This class allows us to not only parse into the database but parse and directly output
    into a XLSX file for further verification, handling and manual validation.

    Examples:

        >>> b = BurpParser()
        >>> b.parse("burpFile.xml")
        Adding issue Content type incorrectly stated
        Adding issue Cacheable HTTPS response
        Adding issue Content type incorrectly stated
        Adding issue Cacheable HTTPS response
        Adding issue Strict transport security not enforced
        >>>
    """

    def __init__(self, workbook: str = "BURP_report.xlsx") -> None:
        self.row: int = 1
        self.col: int = 0
        self.workbook: xlsxwriter.Workbook = xlsxwriter.Workbook(workbook)
        self.header_format: xlsxwriter.Format = self.workbook.add_format()
        self.header_format.set_bold()
        self.header_format.set_align("center")
        self.header_format.set_bg_color("silver")
        self.worksheet: xlsxwriter.Worksheet = self.workbook.add_worksheet(
            "Web Application Findings"
        )
        self.file: str = ""
        self.invalid_tags: List[str] = ["p", "b", "i"]

    def ttext(self, tag: Optional[Tag]) -> str:
        return tag.text if tag and tag.text is not None else ""

    def parse(self, file: str = "burpFile.xml") -> List[Device]:
        """Parse from the XML burp output into a list of Devices

        Examples:
            >>> b = BurpParser()
            >>> devices = b.parse("burpFile.xml")
            Adding issue Content type incorrectly stated to host testphp.vulnweb.com
            Adding issue Cacheable HTTPS response to host testphp.vulnweb.com
            Adding issue Content type incorrectly stated to host testphp.vulnweb.com
            Adding issue Cacheable HTTPS response to host testphp.vulnweb.com
            Adding issue Strict transport security not enforced to host testphp.vulnweb.com
            >>>

        Args:
            file (str): The XML file to parse
        """
        self.file = open(file).read()
        soup: BeautifulSoup = BeautifulSoup(self.file, "xml")
        devices: List[Device] = []

        for issue in soup.find_all("issue"):
            transportLayer = self.ttext(issue.host).split("://")[0]
            fqdn = self.ttext(issue.host).split("://")[1]
            print(f"Adding issue {self.ttext(issue.find('name'))} to host {fqdn}")
            log.debug(f"Adding issue {self.ttext(issue.find('name'))} to host {fqdn}")
            if ":" in fqdn:
                service_port = int(fqdn.split(":")[1])
            elif transportLayer == "https":
                service_port = 443
            elif transportLayer == "http":
                service_port = 80
            else:
                service_port = 0
            hostame = fqdn.split(".")[0]
            for d in devices:
                if fqdn == d.fqdn:
                    device = d
                    break
            else:
                log.debug(f"Creating new device {hostame} with FQDN {fqdn}")
                device = Device(hostname=hostame, fqdn=fqdn)

            for s in device.services:
                if service_port == s.portNumber:
                    service = s
                    break
            else:
                log.debug(
                    f"Adding service {service_port}/{transportLayer} to host {fqdn}"
                )
                service = Service(
                    portNumber=service_port, transport_layer=transportLayer
                )
                device.services.append(service)

            log.debug(
                f"Adding vulnerability {self.ttext(issue.find('name'))} to service {service_port}/{transportLayer} on host {fqdn}"
            )
            vuln = Vulnerability(
                title=self.ttext(issue.find("name")),
                description=self.ttext(issue.issueBackground)
                .replace("<p>", "")
                .replace("</p>", ""),
                mitigation_desc=self.ttext(issue.remediationBackground)
                .replace("<p>", "")
                .replace("</p>", "")
                if issue.remediationBackground
                else "",
            )
            vuln.risk.severity = self.ttext(issue.severity)
            if vuln not in service.vulnerabilities:
                service.vulnerabilities.append(vuln)

            if device not in devices:
                devices.append(device)

        return devices

    def toXLSX(self, file: str = "burpFile.xml") -> None:
        """Parse from file into an XLSX file output"""
        self.file = open(file).read()
        soup = BeautifulSoup(self.file, "xml")

        # Let's setup the worksheet
        self.worksheet.write(0, 0, "Assessment Phase", self.header_format)
        self.worksheet.write(0, 1, "Vulnerability Type", self.header_format)
        self.worksheet.write(0, 2, "Severity", self.header_format)
        self.worksheet.write(0, 3, "Confirmation Status", self.header_format)
        self.worksheet.write(0, 4, "Web Application URL", self.header_format)
        self.worksheet.write(0, 5, "Parameter", self.header_format)
        self.worksheet.write(0, 6, "Attack Value", self.header_format)
        self.worksheet.write(0, 7, "HTTP Method", self.header_format)
        self.worksheet.write(0, 8, "Description", self.header_format)
        self.worksheet.write(0, 9, "Remediation", self.header_format)
        self.worksheet.write(0, 10, "Assigned Resource", self.header_format)
        self.worksheet.write(0, 11, "Remediation Status", self.header_format)
        self.worksheet.write(0, 12, "Completion Date", self.header_format)

        # Let's setup the width of the cells, no autofit, so .. by hand
        self.worksheet.set_column(0, 2, 20)
        self.worksheet.set_column(3, 3, 15)
        self.worksheet.set_column(4, 7, 20)
        self.worksheet.set_column(8, 9, 40)
        self.worksheet.set_column(10, 12, 20)

        self.worksheet.autofilter(0, 0, 0, 9)

        # word_wrap style
        self.long_format = self.workbook.add_format()
        self.long_format.set_text_wrap()

        # Parsing the file with BeautifulSoup
        for issue in soup.find_all("issue"):
            log.debug(f"Adding issue {self.ttext(issue.find('name'))}")
            self.worksheet.write(self.row, self.col, "Application Assessment")
            self.worksheet.write(self.row, self.col + 1, self.ttext(issue.find("name")))
            self.worksheet.write(self.row, self.col + 2, self.ttext(issue.severity))
            self.worksheet.write(self.row, self.col + 3, "Open")
            self.worksheet.write(
                self.row,
                self.col + 4,
                (self.ttext(issue.host) + self.ttext(issue.path)),
            )
            if self.ttext(issue.location).find("parameter") > 0:
                p = self.ttext(issue.location).split(" ")
                parameter = p[1].lstrip("[")
            else:
                parameter = ""
            self.worksheet.write(self.row, self.col + 5, parameter)
            self.worksheet.write(self.row, self.col + 6, "")
            self.worksheet.write(self.row, self.col + 7, "")
            self.worksheet.write(
                self.row,
                self.col + 8,
                self.ttext(issue.issueBackground),
                self.long_format,
            )
            if issue.remediationBackground:
                self.worksheet.write(
                    self.row,
                    self.col + 9,
                    self.ttext(issue.remediationBackground),
                    self.long_format,
                )
            self.worksheet.set_row(self.row, 20)
            self.worksheet.set_column(1, 1, len(self.ttext(issue.find("name"))))
            self.worksheet.set_column(
                4, 4, len(self.ttext(issue.host)) + len(self.ttext(issue.path))
            )
            self.row += 1

        self.workbook.close()
        log.debug(f"XLSX report {self.workbook} created successfully from {file}")
