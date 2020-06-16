import { Component } from '@angular/core';


@Component({
  selector: 'ngx-about',
  styleUrls: ['./about.component.scss'],
  templateUrl: './about.component.html',
})

export class AboutComponent {

  title: string;

  constructor() {
    this.title = "About";
  }

}
