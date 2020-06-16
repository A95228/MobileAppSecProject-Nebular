import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { NbSidebarService } from '@nebular/theme';

interface CardSettings {
  title: string;
  iconClass: string;
  type: string;
}

@Component({
  selector: 'ngx-summary',
  styleUrls: ['./summary.component.scss'],
  templateUrl: './summary.component.html',
})

export class SummaryComponent implements OnInit {
  title: string;
  id: number;
  sub: any;


  constructor(private route: ActivatedRoute,
    private sidebarService: NbSidebarService) {
    this.title = "Zoom.Us";

  }

  ngOnInit() {
    this.sub = this.route.params.subscribe(params => {
      this.id = +params['id'];
    });
  }
}
