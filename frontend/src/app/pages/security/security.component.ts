import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { MatTableDataSource } from '@angular/material/table';


export interface ManifestAnalysis {
  severity: string;
  issue: string;
  description: string;
}

export interface CodeAnalysis {
  severity: string;
  issue: string;
  cvss: number;
  cwe: string;
  owasp: string;
  owasmasvs: string;
  file: string;
}

export interface BinaryAnalysis {
  severity: string;
  issue: string;
  description: string;
  file: string;
}
export interface CodeAnalysis {
  severity: string;
  issue: string;
  cvss: number;
  cwe: string;
  owasp: string;
  owasmasvs: string;
  file: string;
}
export interface AppPermissions {
  severity: string;
  permission: string;
  info: string;
  description: string;
}
const MANIIFESTANALYSIS_DATA: ManifestAnalysis[] = [

  { severity: 'High', issue: 'test', description: "lorem" },

];
const CODEANALYSIS_DATA: CodeAnalysis[] = [
  {
    severity: "High",
    issue: "App can read/write to External Storage. Any App can read data written to External Storage.",
    cvss: 5.6,
    cwe: "CWE-276 Incorrect Default Permissions",
    owasp: "M2: Insecure Data Storage",
    owasmasvs: "MSTG-STORAGE-2",
    file: "/test"
  },

];
const BINARYANALYSIS_DATA: BinaryAnalysis[] = [
  {
    severity: "High",
    issue: "Application Data can be Backed up[android:allowBackup=true]	",

    description: "This flag allows anyone to backup your application data via adb. It allows users who have enabled USB debugging to copy application data off of the device.",
    file: "/test"
  },

];
const APPPERMISSIONS_DATA: AppPermissions[] = [
  {
    severity: "High",
    permission: "android.permission.ACCESS_COARSE_LOCATION",
    info: "coarse (network based) location",
    description: "Access coarse location sources, such as the mobile network database, to determine an approximate phone location, where available. Malicious applications can use this to determine approximately where you are.",
  },

];
@Component({
  selector: 'ngx-summary',
  styleUrls: ['./security.component.scss'],
  templateUrl: './security.component.html',
})


export class SecurityComponent implements OnInit {
  title: string;
  id: number;
  sub: any;
  displayedColumnsManifestAnalysis: string[] = ['severity', 'issue', 'description'];
  displayedColumnsCodeAnalysis: string[] = [  'severity',   'issue',    'cvss',   'cwe', 'owasp', 'owasmasvs', 'file' ];
  displayedColumnsBinaryAnalysis: string[] = [  'severity',   'issue',    'description',   'file' ];
  displayedColumnsAppPermissions: string[] = [  'severity',   'permission',  'info',    'description' ];

  dataSourceManifestAnalysis = new MatTableDataSource(MANIIFESTANALYSIS_DATA);
  dataSourceCodeAnalysis = new MatTableDataSource(CODEANALYSIS_DATA);
  dataSourceBinaryAnalysis = new MatTableDataSource(BINARYANALYSIS_DATA);
  dataAppPermissions = new MatTableDataSource(APPPERMISSIONS_DATA);

  selectedItem = "";
  constructor(private route: ActivatedRoute) {
    this.title = "Zoom.Us";

  }

  ngOnInit() {
    this.sub = this.route.params.subscribe(params => {
      this.id = +params['id'];
    });
    this.dataSourceManifestAnalysis.filterPredicate = (data: ManifestAnalysis, filter: string) => {
      return data.severity == filter;
    };
  }
  applyFilter(filterValue: string) {
    this.dataSourceManifestAnalysis.filter = filterValue;
  }
}
