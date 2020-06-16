import { Injectable } from '@angular/core';
import { of as observableOf,  Observable, BehaviorSubject } from 'rxjs';
import {HttpClient,HttpHeaders} from '@angular/common/http';
import { NbAuthJWTToken, NbAuthService } from '@nebular/auth';
import { takeWhile, map } from 'rxjs/operators';

export class RecentScan {
  image_link: string;
  app_name: string;
  file_name: string;
  system: string;
  timestamp: string;
  timestamp_formated: string; //Dec, 20, 2018
  md5: string;
  package_name: string;
  version_name: string;
  cvss_score: number;
  total_issues: number;
  issue_high: number;
  issue_medium: number;
  issue_low: number;
  security_score: number;
  tracekrs_detection: number;
  status: string; // good bad
  /** added **/

  constructor(
    image_link: string,
    app_name: string,
    file_name: string,
    system: string,
    timestamp: string,
    timestamp_formated: string,
    md5: string,
    package_name: string,
    version_name: string,
    total_issues: number

  ){
    this.image_link = "http://185.230.211.59:8000"+image_link;
    this.app_name = app_name;
    this.file_name = file_name;
    this.system = system;
    this.timestamp = timestamp;
    this.timestamp_formated = timestamp_formated;
    this.md5 = md5;
    this.package_name = package_name;
    this.version_name = version_name;
    this.total_issues = total_issues;

  }
  /** end added **/

}

@Injectable()
export class RecentScanService {
  recentScans: BehaviorSubject<RecentScan[]>;
  httpOptions = {};

  constructor(private authService: NbAuthService,private http: HttpClient) {
    this.recentScans = new BehaviorSubject<RecentScan[]>([]);
    this.authService.onTokenChange()
      .subscribe((token: NbAuthJWTToken) => {
        if (token.isValid()) {
          this.httpOptions = {  headers: new HttpHeaders({ "Authorization": "Bearer " + token.getValue() } ) };
        }
      });
  }



  setValue(newValue): void {
    this.recentScans.next(newValue);
  }
  getValue(): Observable<RecentScan[]> {
    return this.recentScans.asObservable();
  }
  public getRecentScans(){


    return this.http.get('http://185.230.211.59:8000/api/v1/recent_scans', this.httpOptions)
    /** added **/
    .pipe(
    map((data: any)=> {
          console.log(data);
          var returnArray = [];
          data.forEach(item => {
            returnArray.push(
              new RecentScan(
               item.scan.icon_url,
               item.scan.app_info.app_name,
               item.scan.app_info.file_name,
               item.scan.app_info.system,
               item.scan.app_info.timestamp_formated,
               item.scan.app_info.timestamp_formated,
               item.scan.app_info.md5,
               item.scan.app_info.package_name,
               item.scan.app_info.version_name,
               item.seco.binary.high+item.seco.binary.medium + item.seco.binary.info +  item.seco.code.high+item.seco.code.medium + item.seco.code.info + item.seco.manifest.high+item.seco.manifest.medium + item.seco.manifest.info
             )
            );
          });

          return returnArray;

      })
      );
      /** end added **/

  }

  public addRecentScans(data){
    return this.http.post('http://185.230.211.59:8000/api/v1/scan', data, this.httpOptions);
  }

}
