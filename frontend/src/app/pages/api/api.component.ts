import { Component } from '@angular/core';
import { MatTableDataSource } from '@angular/material/table';

export interface ApiElement {
  paramname: string;
  paramvalue: string;
  required: string;
}
const ELEMENT_DATA: ApiElement[] = [

  { paramname: 'file', paramvalue: 'multipart/form-data', required: 'Yes'},

];
@Component({
  selector: 'ngx-api',
  styleUrls: ['./api.component.scss'],
  templateUrl: './api.component.html',
})

export class ApiComponent{
  title: string;
  dataSource = new MatTableDataSource(ELEMENT_DATA);
  displayedColumns: string[] = ['paramname', 'paramvalue', 'required'];

  constructor() {
    this.title = "Api Docs";
  }

}
