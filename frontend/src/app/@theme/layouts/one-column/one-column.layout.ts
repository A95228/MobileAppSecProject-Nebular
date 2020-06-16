import { Component, Input, OnInit } from '@angular/core';
import { NbMenuService, NbSidebarService } from '@nebular/theme';
import { Router } from '@angular/router';

@Component({
  selector: 'ngx-one-column-layout',
  styleUrls: ['./one-column.layout.scss'],
  template: `
    <nb-layout windowMode>
      <nb-layout-header fixed>
        <ngx-header></ngx-header>

      </nb-layout-header>
      <nb-sidebar class="menu-sidebar" tag="menu-sidebar">
        <div class="logo-container">
          <a class="logo" href="#" (click)="navigateHome()"><img src="assets/images/logo.png"></a>
        </div>
        <div class="search">
          <mat-icon  aria-hidden="false">search</mat-icon>
          <input type="text" placeholder="Search">
        </div>
      </nb-sidebar>

      <nb-sidebar state="collapsed" class="menu-sidebar-scan" tag="notifications" right fixed>

      </nb-sidebar>
      <nb-sidebar  state="{{ status }}" class="menu-sidebar-scan" tag="new-scan" fixed>
        <div  class="upload">
          <h2>Scan an app</h2>
          <h3>Upload or drag .apk or .ipa files to scan</h3>
          <ngx-upload-drapndrop></ngx-upload-drapndrop>
        </div>
      </nb-sidebar>

      <nb-layout-column>
        <ng-content select="router-outlet"></ng-content>
      </nb-layout-column>

    </nb-layout>
  `,
})
export class OneColumnLayoutComponent implements OnInit {
  status: string = "";

  constructor(private menuService: NbMenuService,
    private sidebarService: NbSidebarService,
    private router: Router) {

  }
  ngOnInit() {
    if (this.router.url === '/pages/home' ||
        this.router.url === '/pages/team' ||
        this.router.url === '/pages/api' ||
        this.router.url === '/pages/about' ||
        this.router.url === '/pages/profile'
      ) {
      this.status = "expanded";
    } else {
      this.status = "expanded";
    }
  }

  navigateHome() {
    this.menuService.navigateHome();
    return false;
  }
}
