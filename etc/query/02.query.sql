
CREATE DATABASE webdb;

create user 'webuser'@'localhost' IDENTIFIED by 'webuser';

grant all privileges on webdb.* to 'webuser'@'localhost';

flush privileges;




select now();

create table tbl_todo (
                          tno int auto_increment primary key,
                          title varchar(100) not null,
                          dueDate date not null,
                          finished tinyint default 0
);

insert into tbl_todo (title, dueDate, finished)
values ('Test...', '2022-12-31', 1);

select * from tbl_todo;

select * from tbl_todo where tno = '5';

select * from tbl_todo where tno < '10';

update tbl_todo set finished = 0, title = 'Not Yet...1' where tno = '5';

delete from tbl_todo where tno > '6';



create table tbl_member (
  mid varchar(50) primary key,
  mpw varchar(50) not null,
  mname varchar(100) not null
);

alter table tbl_member add column uuid varchar(50);

insert into tbl_member(mid, mpw, mname) values ('user00','1111','사용자0');
insert into tbl_member(mid, mpw, mname) values ('user01','1111','사용자0');
insert into tbl_member(mid, mpw, mname) values ('user02','1111','사용자0');

select * from tbl_member where mid = 'user00' and mpw = '1111';




drop table tbl_todo;

create table tbl_todo (
                          tno int auto_increment primary key,
                          title varchar(100) not null,
                          dueDate date not null,
                          writer varchar(50) not null,
                          finished tinyint default 0
);

select * from tbl_todo;

/* dummy data*/
insert into tbl_todo(title,dueDate,writer) (select title, dueDate, writer from tbl_todo);

select * from tbl_todo order by tno desc;

select count(*) from tbl_todo;

select * from tbl_todo order by tno desc limit 10;

select * from tbl_todo order by tno desc limit 10, 10;


SHOW VARIABLES LIKE 'character_set%';
SHOW VARIABLES LIKE 'collation%';

ALTER DATABASE webdb CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci;


select * from board order by bno desc;


select * from board_image order by board_bno desc;

select * from board order by bno asc;



SELECT
    b1_0.bno,
    b1_0.content,
    b1_0.moddate,
    b1_0.regdate,
    b1_0.title,
    b1_0.writer
FROM
    from board b1_0
WHERE
    b1_0.bno=1


select * from board order by bno desc;

select * from reply order by rno desc;

select * from board_image order by board_bno desc;


-- 댓글 복사
insert into reply(moddate,regdate, reply_text,replyer,board_bno)
select moddate, regdate, reply_text, replyer, board_bno from reply;

delete from board_image where board_bno is null;

create table persistent_logins (
    username varchar(64) not null,
    series varchar(64) primary key,
    token varchar(64) not null,
    last_used timestamp not null
);

select * from persistent_logins;

select * from member;

select * from member_role_set;