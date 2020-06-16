import { Component, OnDestroy, OnInit } from '@angular/core';
import { Location } from "@angular/common";
import { Router, Event, RouterEvent } from "@angular/router";
import { NbMediaBreakpointsService, NbMenuService, NbSidebarService, NbThemeService } from '@nebular/theme';

import { UserData } from '../../../@core/data/users';
import { LayoutService } from '../../../@core/utils';
import { map, takeUntil, filter } from 'rxjs/operators';
import { Subject } from 'rxjs';

@Component({
  selector: 'ngx-header',
  styleUrls: ['./header.component.scss'],
  templateUrl: './header.component.html',
})
export class HeaderComponent implements OnInit, OnDestroy {

  private destroy$: Subject<void> = new Subject<void>();
  userPictureOnly: boolean = false;
  user: any;
  themes = [
    {
      value: 'default',
      name: 'Light',
    },
    {
      value: 'dark',
      name: 'Dark',
    },
    {
      value: 'cosmic',
      name: 'Cosmic',
    },
    {
      value: 'corporate',
      name: 'Corporate',
    },
  ];

  currentTheme = 'default';
  linkTeam = false;
  linkSupport = false;
  linkAbout = false;
  linkApiDocs = false;
  linkReport = false;
  routerlink: string;
  userMenu = [{ title: 'Profile', link: '/pages/profile' }, { title: 'Log out', link: '/auth/logout' }];

  constructor(private sidebarService: NbSidebarService,
    private menuService: NbMenuService,
    private themeService: NbThemeService,
    private userService: UserData,
    private layoutService: LayoutService,
    private breakpointService: NbMediaBreakpointsService,
    private location: Location,
    private router: Router) {


  }

  ngOnInit() {
    this.currentTheme = this.themeService.currentTheme;
    this.menuFunc(this.router.url);
    this.router.events.pipe(
      filter((e: Event): e is RouterEvent => e instanceof RouterEvent)
    ).subscribe((e: RouterEvent) => {
      this.menuFunc(e.url);
    });
    this.userService.getUsers()
      .pipe(takeUntil(this.destroy$))
      .subscribe((users: any) => this.user = users.nick);

    const { xl } = this.breakpointService.getBreakpointsMap();
    this.themeService.onMediaQueryChange()
      .pipe(
        map(([, currentBreakpoint]) => currentBreakpoint.width < xl),
        takeUntil(this.destroy$),
    )
      .subscribe((isLessThanXl: boolean) => this.userPictureOnly = isLessThanXl);

    this.themeService.onThemeChange()
      .pipe(
        map(({ name }) => name),
        takeUntil(this.destroy$),
    )
      .subscribe(themeName => this.currentTheme = themeName);
  }

  ngOnDestroy() {
    this.destroy$.next();
    this.destroy$.complete();
  }

  changeTheme(themeName: string) {
    this.themeService.changeTheme(themeName);
  }

  toggleSidebar(): boolean {
    this.sidebarService.toggle(true, 'menu-sidebar');
    this.layoutService.changeLayoutSize();

    return false;
  }
  menuFunc(router): void{
    if (router === '/pages/team') {
      this.resetMenu();
      this.linkTeam = true;
      this.routerlink = "home";
    } else if (router === '/pages/support') {
      this.resetMenu();
      this.linkSupport = true;
      this.routerlink = "home";
    } else if (router === '/pages/about') {
      this.resetMenu();
      this.linkAbout = true;
      this.routerlink = "home";
    } else if (router === '/pages/api') {
      this.resetMenu();
      this.linkApiDocs = true;
      this.routerlink = "home";
    } else {
      this.resetMenu();
      this.linkReport = true;
      this.routerlink = router;
    }
  }
  resetMenu(): void {
    this.linkTeam = false;
    this.linkSupport = false;
    this.linkAbout = false;
    this.linkApiDocs = false;
    this.linkReport = false;
  }
  toggleNotifications(){
    this.sidebarService.toggle(false,"notifications-right");
  }


}
