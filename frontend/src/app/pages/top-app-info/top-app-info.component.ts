import { Component, OnDestroy } from '@angular/core';
import { NbThemeService } from '@nebular/theme';
import { takeWhile } from 'rxjs/operators';
import { SolarData } from '../../@core/data/solar';
import { Router } from '@angular/router';
import { NbSidebarService } from '@nebular/theme';

@Component({
  selector: 'top-app-info',
  styleUrls: ['./top-app-info.component.scss'],
  templateUrl: './top-app-info.component.html',
})

export class TopAppInfoComponent implements OnDestroy {
  title: string;
  items = [
    { title: 'Print' },
    { title: 'PDF' },
    { title: 'Share' },
  ];
  single = [
    {
      name: 'High',
      value: 60,
    },
    {
      name: 'Medium',
      value: 30,
    },
    {
      name: 'Low',
      value: 10,
    },
  ];
  view: any[] = [130, 130];
  colorScheme = {
    domain: ['#FF6767', '#FFCC67', '#10D480']
  };
  backdrop = false;
  backdropJava = false;
  backdropSamali = false;
  themeSubscription: any;

  constructor(private router: Router,
    private sidebarService: NbSidebarService) {
  }
  toggleRight() {
    this.sidebarService.toggle(false, 'summary-right');
    if (this.backdrop)
      this.backdrop = false;
    else
      this.backdrop = true;
  }
  toggleRightSamali() {
    this.sidebarService.toggle(false, 'samali-right');
    if (this.backdropSamali)
      this.backdropSamali = false;
    else
      this.backdropSamali = true;
  }
  toggleRightJava() {
    this.sidebarService.toggle(false, 'java-right');
    if (this.backdropJava)
      this.backdropJava = false;
    else
      this.backdropJava = true;
  }
  toggleNewScan() {
    this.sidebarService.toggle(false,'new-scan');
  }

  ngOnDestroy(): void {
    //  this.themeSubscription.unsubscribe();
  }


}
