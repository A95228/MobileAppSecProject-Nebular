import { Component, OnInit } from '@angular/core';
import { takeWhile } from 'rxjs/operators';
import { SolarData } from '../../@core/data/solar';
import { Router } from '@angular/router';
import { NbSidebarService } from '@nebular/theme';
import { RecentScanService, RecentScan } from '../../@core/utils/recent-scans';

@Component({
  selector: 'ngx-home',
  styleUrls: ['./home.component.scss'],
  templateUrl: './home.component.html',
})

export class HomeComponent implements OnInit {
  title: string;
  empty: boolean;
  recentScans: RecentScan[];

  constructor(private router: Router,
    private sidebarService: NbSidebarService,
    private service: RecentScanService) {
    this.title = "Reports";
  }

  ngOnInit() {
    this.service.getRecentScans()

      .subscribe((data: RecentScan[]) => {
        if (data.length != 0) {
          this.service.setValue(data);
          this.service.getValue().subscribe((value) => {
            this.recentScans = value;
            console.log(value);
          });
        } else {
          this.empty = true;
        }

      });
  }

}
