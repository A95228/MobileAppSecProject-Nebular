import { Injectable } from '@angular/core';
import { of as observableOf,  Observable, BehaviorSubject } from 'rxjs';


@Injectable()
export class UploadService {

  progress: BehaviorSubject<number>;
  close: BehaviorSubject<boolean>;

  constructor() {
    this.progress = new BehaviorSubject<number>(0);
    this.close = new BehaviorSubject<boolean>(false);

  }


    setCloseValue(newValue): void {
      this.close.next(newValue);
    }
    getCloseValue(): Observable<boolean> {
      return this.close.asObservable();
    }



  setValue(newValue): void {
    this.progress.next(newValue);
  }
  getValue(): Observable<number> {
    return this.progress.asObservable();
  }


}
