import { Component, EventEmitter, Output, Input, OnInit, SimpleChanges, TemplateRef } from '@angular/core';
import { UploadOutput, UploadInput, UploadFile, humanizeBytes, UploaderOptions } from 'ngx-uploader';
import { NbAuthJWTToken, NbAuthService } from '@nebular/auth';
import { NbDialogService } from '@nebular/theme';
import { UploadTabComponent } from './tab/tab.component';
import { UploadService } from './upload.service';
import { RecentScanService, RecentScan } from '../../@core/utils/recent-scans';
import { takeWhile, map } from 'rxjs/operators';
@Component({
  selector: 'ngx-upload-drapndrop',
  templateUrl: './upload.component.html',
  styleUrls: ['./upload.component.scss']
})
export class UploadComponent implements OnInit {


  imgURL: any;

  @Input() uploadCMD: boolean;
  @Input() type: string;
  @Output() verifyFile = new EventEmitter<boolean>();
  @Output() message = new EventEmitter<string>();
  recentScans: RecentScan[];
  close: boolean;
  options: UploaderOptions;
  formData: FormData;
  files: UploadFile;
  uploadInput: EventEmitter<UploadInput>;
  humanizeBytes: Function;
  progress: number;
  dragOver: boolean;
  constructor(private uploadService: UploadService,
    private dialogService: NbDialogService,
    private recentScanService: RecentScanService,
    private authService: NbAuthService) {
    this.progress = 0;
    this.options = { concurrency: 1 };
    this.uploadInput = new EventEmitter<UploadInput>(); // input events, we use this to emit data to ngx-uploader
    this.humanizeBytes = humanizeBytes;

  }

  ngOnInit() {
    this.recentScanService.getValue().subscribe((value) => {
      this.recentScans = value;
    });
    this.uploadService.getCloseValue().subscribe((value) => {
      console.log(value);
      if (value) {
        this.cancelUpload(this.files.id);
        this.removeAllFiles();
        this.uploadService.setCloseValue(false);

      }
    });
  }

  onUploadOutput(output: UploadOutput): void {
    switch (output.type) {
      case 'allAddedToQueue':
        // uncomment this if you want to auto upload files when added
        this.open();
        this.authService.onTokenChange()
          .subscribe((token: NbAuthJWTToken) => {
            if (token.isValid()) {
              console.log(token.isValid());
              const event: UploadInput = {
                type: 'uploadAll',
                url: 'http://185.230.211.59:8000/api/v1/upload_scan',
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + token.getValue() },
                data: {},
                includeWebKitFormBoundary: true // <----  set WebKitFormBoundary

              };

              this.uploadInput.emit(event);
            }

          });
        break;
      case 'addedToQueue':
        if (typeof output.file !== 'undefined') {
          console.log('queue')
          this.files = output.file;
          this.startUpload();

        }
        break;
      case 'uploading':
        if (typeof output.file !== 'undefined') {
          // update current data in files array for uploading file
          //const index = this.files.findIndex((file) => typeof output.file !== 'undefined' && file.id === output.file.id);
          this.files = output.file;

          this.uploadService.setValue(this.files.progress.data.percentage*0.8);
        }
        break;
      case 'removed':
        // remove file from array when removed
        this.files = null;
        break;
      case 'dragOver':
        this.dragOver = true;
        break;
      case 'dragOut':
      case 'drop':
        this.dragOver = false;
        break;
      case 'done':
        // The file is downloaded

         // this.recentScanService.addRecentScans().subscribe((value) => {
         //   this.recentScans = value;
         // });
         var recentscan = this.files.response
         /** added **/

         .pipe(
         map((item: any)=> {

               return new RecentScan(
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
               })
           );
           /** end added **/

        this.uploadService.setValue(100);
        console.log(this.files.response);

        break;
    }
  }

  startUpload(): void {
    console.log("token.isValid()");
  }

  open() {
    const activeModal = this.dialogService.open(UploadTabComponent, {
        hasBackdrop: true,
        closeOnBackdropClick: false
    });
    console.log(activeModal);
    //activeModal.componentRef.instance.progress = this.progress;
  }
  cancelUpload(id: string): void {
    this.uploadInput.emit({ type: 'cancel', id: id });
  }

  removeFile(id: string): void {
    this.uploadInput.emit({ type: 'remove', id: id });
  }

  removeAllFiles(): void {
    this.uploadInput.emit({ type: 'removeAll' });
    this.imgURL = null;
    this.files = null;

  }

  public verify(files) {
    return true;
  }

}
