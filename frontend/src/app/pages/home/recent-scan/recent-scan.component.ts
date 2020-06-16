import { Component, Input } from '@angular/core';
import { Router } from '@angular/router';
import { NbSidebarService } from '@nebular/theme';
import { RecentScan } from '../../../@core/utils/recent-scans';

@Component({
  selector: 'ngx-recent-scan',
  templateUrl: './recent-scan.component.html',
  styleUrls: ['./recent-scan.component.scss']
})
export class RecentScanComponent {
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
  themeSubscription: any;
  @Input() recentScans: RecentScan[];
  constructor(private router: Router,
    private sidebarService: NbSidebarService) {
  }

  navigateToSummary(): void {
    this.sidebarService.toggle(false, 'new-scan');
  }
  redirect(md5: string){
    this.router.navigate(['summary', md5]);
  }
}
