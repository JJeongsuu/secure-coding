# Secure Coding

## Tiny Secondhand Shopping Platform.

You should add some functions and complete the security requirements.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/ugonfor/secure-coding
conda env create -f enviroments.yaml
```

## usage

run the server process.

```
python app.py
```

if you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```

## 기본 관리자 계정

아이디 : admin
비밀번호 : admin123             





앱 실행시 ensure_admin 함수에 의해 자동생성됩니다. 


## 주요 기능
- 사용자 회원가입, 로그인, 로그아웃, 프로필관리
- 새 상품 등록 -> 상품 이름, 설명, 가격, 이미지
- 상품 수정, 삭제, 검색
- 실시간 채팅
- 악의적인 사용자 신고(차단)
- 송금 기능 -> 잔액표시, 송금 대상, 금액, 송금자 비밀번호 확인
- 로그아웃
- 관리자 페이지 -> 사용자 목록, 상품 목록, 송금내역, 신고 목록(신고 상태 변경, 삭제 등 통제 가능)